"""
The proxy module provides the means to proxy images from other registry instances.
Registries following the distribution spec are supported.
"""
from __future__ import annotations
from typing import Any
import re
import json

import requests

from app import model_cache
from data.cache import cache_key
from data.database import ProxyCacheConfig


WWW_AUTHENTICATE_REGEX = re.compile(r'(\w+)[=] ?"?([^",]+)"?')
TOKEN_VALIDITY_LIFETIME_S = 60 * 60  # 1 hour, in seconds - Quay's default
TOKEN_RENEWAL_THRESHOLD = 10  # interval (in seconds) when to renew auth token


REGISTRY_URLS = {"docker.io": "registry-1.docker.io"}


def parse_www_auth(value: str) -> dict[str, str]:
    """
    Parses WWW-Authenticate parameters and returns a dict of key=val.
    See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
    for details.
    This parser is *not* fully compliant with RFC 7235, notably it does not support
    multiple challenges.
    """
    scheme = value.split(" ", 1)[0]
    matches = WWW_AUTHENTICATE_REGEX.findall(value)
    parsed = dict(matches)
    if scheme:
        parsed["scheme"] = scheme
    return parsed


class Proxy:
    def __init__(self, config: ProxyCacheConfig, repository: str):
        self._config = config

        hostname = REGISTRY_URLS.get(
            config.upstream_registry_hostname,
            config.upstream_registry_hostname,
        )
        url = f"https://{hostname}"
        if config.insecure:
            url = f"http://{hostname}"

        self.base_url = url
        self._session = requests.Session()
        self._repo = repository
        self._authorize(self._credentials())

    def get_manifest(self, image_ref: str, media_type: str | None = None) -> dict[str, Any]:
        headers = {}
        if media_type is not None:
            headers["Accept"] = media_type

        url = f"{self.base_url}/v2/{self._repo}/manifests/{image_ref}"
        resp = self.get(url, headers=headers)
        return {
            "response": self._wrap_error(resp),
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }

    def manifest_exists(self, image_ref, media_type=None):
        url = f"{self.base_url}/v2/{self._repo}/manifests/{image_ref}"
        headers = {}
        if media_type is not None:
            headers["Accept"] = media_type
        resp = self.head(url, headers=headers, allow_redirects=True)
        return {
            "response": resp.text,
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }

    def get_blob(self, digest: str, media_type: str | None = None):
        headers = {}
        if media_type is not None:
            headers["Accept"] = media_type

        url = f"{self.base_url}/v2/{self._repo}/blobs/{digest}"
        resp = self.get(
            url,
            headers=headers,
            allow_redirects=True,
            stream=True,
        )
        if not resp.ok:
            return {
                "response": self._wrap_error(resp),
                "status": resp.status_code,
                "headers": dict(resp.headers),
            }

        return {
            "response": resp.content,
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }

    def blob_exists(self, digest: str):
        url = f"{self.base_url}/v2/{self._repo}/blobs/{digest}"
        resp = self.head(url, allow_redirects=True)
        return {
            "response": resp.text,
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }

    def get(self, *args, **kwargs) -> requests.Response:
        """
        Wrapper for session.get for renewing auth tokens and retrying requests in case of 401.
        """
        return self._request(self._session.get, *args, **kwargs)

    def head(self, *args, **kwargs) -> requests.Response:
        """
        Wrapper for session.head for renewing auth tokens and retrying requests in case of 401.
        """
        return self._request(self._session.head, *args, **kwargs)

    def _request(self, request_func, *args, **kwargs) -> requests.Response:
        resp = request_func(*args, **kwargs)
        if resp.status_code == 401:
            self._authorize(self._credentials(), force_renewal=True)
            resp = request_func(*args, **kwargs)
        return resp

    def _credentials(self) -> tuple[str, str] | None:
        auth = None
        username = self._config.upstream_registry_username
        password = self._config.upstream_registry_password
        if username is not None and password is not None:
            auth = (username.decrypt(), password.decrypt())
        return auth

    def _wrap_error(self, resp: requests.Response) -> bytes:
        errors = resp.json().get("errors", [])
        if len(errors) == 0:
            return resp.text

        orig_msg = errors[0].get("message")
        req = resp.request
        errors[0]["message"] = f"{req.method} {req.url}: {orig_msg}"
        return json.dumps({"errors": errors})

    def _authorize(self, auth: tuple[str, str] | None = None, force_renewal: bool = False) -> None:
        raw_token = model_cache.retrieve(self._cache_key(), lambda: None)
        if raw_token is not None and not force_renewal:
            token = raw_token["token"]
            if isinstance(token, bytes):
                token = token.decode("ascii")
            self._session.headers["Authorization"] = f"Bearer {token}"
            return

        if force_renewal:
            self._session.headers.pop("Authorization", None)

        # the /v2/ endpoint returns 401 when the client is not authorized.
        # if we get 200, there's no need to proceed.
        resp = self._session.get(f"{self.base_url}/v2/")
        if resp.status_code == 200:
            return

        www_auth = parse_www_auth(resp.headers.get("www-authenticate", ""))
        scheme = www_auth.get("scheme")
        service = www_auth.get("service")
        realm = www_auth.get("realm")

        if scheme == "Basic":
            # attach basic auth header to session
            requests.auth.HTTPBasicAuth(auth[0], auth[1])(self._session)
            return

        scope = f"repository:{self._repo}:pull"
        auth_url = f"{realm}?service={service}&scope={scope}"

        basic_auth = None
        if auth is not None:
            basic_auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])

        resp = self._session.get(auth_url, auth=basic_auth)
        if not resp.ok:
            raise Exception(f"Failed to get token from '{auth_url}', {resp.status_code}")

        resp_json = resp.json()
        token = resp_json.get("token")

        # our cached token will expire a few seconds (TOKEN_RENEWAL_THRESHOLD)
        # before the actual token expiration.
        # we do this so that we can renew the token before actually hitting
        # any 401s, to save some http requests.
        expires_in = resp_json.get("expires_in", TOKEN_VALIDITY_LIFETIME_S)
        expires_in -= TOKEN_RENEWAL_THRESHOLD
        model_cache.retrieve(self._cache_key(expires_in), lambda: {"token": token})
        self._session.headers["Authorization"] = f"{scheme} {token}"

    def _cache_key(self, expires_in=TOKEN_VALIDITY_LIFETIME_S):
        key = cache_key.for_upstream_registry_token(
            self._config.organization.username,
            self._repo,
            f"{expires_in}s",
        )
        return key
