import unittest

from httmock import urlmatch, response, HTTMock

from proxy import Proxy, parse_www_auth


class TestWWWAuthParser(unittest.TestCase):
    realm = "https://auth.docker.io/token"
    service = "registry.docker.io"

    def test_parse_realm(self):
        header = f'Bearer realm="{self.realm}",service="{self.service}"'
        parsed = parse_www_auth(header)
        self.assertEqual(parsed["realm"], self.realm)

    def test_parse_service(self):
        header = f'Bearer realm="{self.realm}",service="{self.service}"'
        parsed = parse_www_auth(header)
        self.assertEqual(parsed["service"], self.service)

    def test_parse_empty(self):
        parsed = parse_www_auth("")
        self.assertEqual(parsed, {})


def docker_registry_mock_401(url, request):
    headers = {
        "www-authenticate": 'Bearer realm="https://auth.docker.io/token",service="registry.docker.io"'
    }
    content = {
        "errors": [
            {
                "code": "UNAUTHORIZED",
                "message": "authentication required",
                "detail": None,
            }
        ]
    }
    return response(401, content, headers)


ANONYMOUS_TOKEN = "anonymous-token"
USER_TOKEN = "user-token"


def docker_auth_mock(url, request):
    token = ANONYMOUS_TOKEN
    auth_header = request.headers.get("Authorization", None)
    if auth_header is not None:
        token = USER_TOKEN

    content = {
        "token": token,
        "access_token": "access-token",
        "expires_in": 300,
        "issued_at": "2022-01-11T15:28:36.272470279Z",
    }
    return response(200, content)


def docker_registry_manifest(url, request):
    content = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 10231,
            "digest": "sha256:07e2ee723e2d9c8c141137bf9de1037fd2494248e13da2805a95ad840f61dd6c",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 31357624,
                "digest": "sha256:a2abf6c4d29d43a4bf9fbb769f524d0fb36a2edab49819c1bf3e76f409f953ea",
            }
        ],
    }
    return response(200, content)


def docker_registry_manifest_404(url, request):
    content = {
        "errors": [
            {"code": "MANIFEST_UNKNOWN", "message": "manifest unknown", "detail": "unknown tag=666"}
        ]
    }
    return response(404, content)


@urlmatch(netloc=r"(.*\.)?docker\.io")
def docker_registry_mock(url, request):
    if url.netloc == "registry-1.docker.io":
        if url.path == "/v2" or url.path == "/v2/":
            return docker_registry_mock_401(url, request)
        elif url.path == "/v2/library/postgres/manifests/14":
            return docker_registry_manifest(url, request)
        elif url.path == "/v2/library/postgres/manifests/666":
            return docker_registry_manifest_404(url, request)
    elif url.netloc == "auth.docker.io":
        return docker_auth_mock(url, request)

    msg = {
        "errors": [
            {"message": f"Oops, this endpoint isn't mocked. requested {url.netloc}/{url.path}"}
        ]
    }
    return response(404, msg)


class TestProxy(unittest.TestCase):
    def test_anonymous_auth_sets_session_token(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy("registry-1.docker.io", "library/postgres")
            self.assertEqual(
                proxy.session.headers.get("Authorization"), f"Bearer {ANONYMOUS_TOKEN}"
            )

    def test_auth_with_user_creds_set_session_token(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy("registry-1.docker.io", "library/postgres", auth=("user", "pass"))
            self.assertEqual(proxy.session.headers.get("Authorization"), f"Bearer {USER_TOKEN}")

    def test_get_manifest(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy("registry-1.docker.io", "library/postgres")
            manifest = proxy.get_manifest(
                image_ref="14", media_type="application/vnd.docker.distribution.manifest.v2+json"
            )
            self.assertEqual(
                list(manifest.keys()), ["schemaVersion", "mediaType", "config", "layers"]
            )

    def test_get_manifest_404(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy("registry-1.docker.io", "library/postgres")
            with self.assertRaises(Exception) as cm:
                manifest = proxy.get_manifest(
                    image_ref="666",
                    media_type="application/vnd.docker.distribution.manifest.v2+json",
                )
        unknown_manifest = {
            "code": "MANIFEST_UNKNOWN",
            "message": "manifest unknown",
            "detail": "unknown tag=666",
        }
        error = cm.exception.args[0].get("errors", [{}])[0]
        self.assertEqual(unknown_manifest, error)
