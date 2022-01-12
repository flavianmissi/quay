"""
The proxy module provides the means to proxy images from other registry instances.
Registries following the distribution spec are supported.
"""
from __future__ import annotations
import re

import requests


WWW_AUTHENTICATE_REGEX = re.compile(r'(\w+)[=] ?"?([^",]+)"?')


class Proxy:

    def __init__(self, registry: str, repository: str, auth: tuple[str, str] | None = None):
        self.url = "https://" + registry + "/v2/"
        self.session = requests.Session()
        self._repo = repository
        self._authorize(self._get_auth_url(), auth)

    def _get_auth_url(self) -> str:
        resp = self.session.get(self.url)
        www_auth = dict(
            WWW_AUTHENTICATE_REGEX.findall(resp.headers.get("www-authenticate"))
        )
        service = www_auth["service"]
        scope = f"repository:{self._repo}:pull"
        auth_url = www_auth["realm"] + f"?service={service}&scope={scope}"
        print(auth_url)

        return auth_url

    def _authorize(self, auth_url: str, auth: tuple[str, str] | None = None):
        basic_auth = None
        if auth is not None:
            basic_auth = requests.auth.HTTPBasicAuth(auth[0], auth[1])

        resp = self.session.get(auth_url, auth=basic_auth)
        if not resp.ok:
            raise Exception(f"Failed to get token from '{auth_url}', {resp.status_code}")

        token = resp.json().get("token")
        self.session.headers["Authorization"] = f"Bearer {token}"
