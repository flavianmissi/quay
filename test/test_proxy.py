import unittest

from httmock import urlmatch, response, HTTMock

from proxy import Proxy

def docker_registry_mock_401(url, request):
    headers = {
        "www-authenticate": "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\""
    }
    content = {
        "errors": [{
            "code": "UNAUTHORIZED",
            "message": "authentication required",
            "detail": None,
        }]
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
        "issued_at": "2022-01-11T15:28:36.272470279Z"
    }
    return response(200, content)


@urlmatch(netloc=r'(.*\.)?docker\.io')
def docker_registry_mock(url, request):
    if url.netloc == "registry-1.docker.io":
        return docker_registry_mock_401(url, request)
    elif url.netloc == "auth.docker.io":
        return docker_auth_mock(url, request)
    return response(404, f"ops, this endpoint isn't mocked. requested {url.netloc}")


class TestProxy(unittest.TestCase):

    def test_anonymous_auth_sets_session_token(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy("registry-1.docker.io", "library/postgres")
            self.assertEqual(
                proxy.session.headers.get("Authorization"),
                f"Bearer {ANONYMOUS_TOKEN}"
            )

    def test_auth_with_user_creds_set_session_token(self):
        with HTTMock(docker_registry_mock):
            proxy = Proxy(
                "registry-1.docker.io",
                "library/postgres",
                auth=("user", "pass"))
            self.assertEqual(
                proxy.session.headers.get("Authorization"),
                f"Bearer {USER_TOKEN}"
            )
