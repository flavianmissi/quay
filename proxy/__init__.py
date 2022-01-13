"""
The proxy module provides the means to proxy images from other registry instances.
Registries following the distribution spec are supported.
"""
from __future__ import annotations
from typing import Any
from urllib.parse import urlparse
import re

import requests


# BLOB_CONTENT_TYPE = "application/octet-stream"
DEFAULT_SCHEME = "https"
WWW_AUTHENTICATE_REGEX = re.compile(r'(\w+)[=] ?"?([^",]+)"?')


def parse_www_auth(value: str) -> dict[str, str]:
    """
    Parses WWW-Authenticate parameters and returns a dict of key=val.
    See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate
    for details.
    """
    matches = WWW_AUTHENTICATE_REGEX.findall(value)
    return dict(matches)


class Proxy:
    def __init__(self, registry: str, repository: str, auth: tuple[str, str] | None = None):
        url = registry.rstrip("/")
        if not registry.startswith("http"):
            url = f"{DEFAULT_SCHEME}://{registry}"
        self.base_url = url
        self.session = requests.Session()
        self._repo = repository
        self._authorize(auth)

    def get_manifest(self, image_ref: str, media_type: str | None = None) -> dict[str, Any]:
        headers = {}
        if media_type is not None:
            headers["Accept"] = media_type

        url = f"{self.base_url}/v2/{self._repo}/manifests/{image_ref}"
        resp = self.session.get(
            url,
            headers=headers,
        )
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
        resp = self.session.get(
            url,
            headers=headers,
            allow_redirects=True,
            stream=True,
        )
        if not resp.ok:
            return {
                "response": resp.text,
                "status": resp.status_code,
                "headers": dict(resp.headers),
            }

        def stream_contents():
            chunk = 1024
            for chunk in resp.iter_content(chunk_size=chunk):
                yield chunk

        # blob_size = int(resp.headers.get("Content-Length"))
        # headers = {
        #     "Docker-Content-Digest": digest,
        #     "Content-Type": BLOB_CONTENT_TYPE,
        #     "Content-Length": blob_size,
        # }
        # accept_ranges = resp.headers.get("Accept-Ranges", None)
        # if accept_ranges is not None:
        #     headers["Accept-Ranges"] = accept_ranges
        return {
            "response": stream_contents(),
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }

    def _authorize(self, auth: tuple[str, str] | None = None):
        resp = self.session.get(f"{self.base_url}/v2/")

        # the /v2/ endpoint returns 401 when the client is not authorized.
        # if we get 200, there's no need to proceed.
        if resp.status_code == 200:
            return

        www_auth = parse_www_auth(resp.headers.get("www-authenticate", ""))
        service = www_auth.get("service")
        realm = www_auth.get("realm")

        scope = f"repository:{self._repo}:pull"
        auth_url = f"{realm}?service={service}&scope={scope}"
        basic_auth = None
        if auth is not None:
            basic_auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])

        resp = self.session.get(auth_url, auth=basic_auth)
        if not resp.ok:
            raise Exception(f"Failed to get token from '{auth_url}', {resp.status_code}")

        token = resp.json().get("token")
        self.session.headers["Authorization"] = f"Bearer {token}"
