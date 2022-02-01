import unittest
import pytest
import time
from unittest.mock import patch, MagicMock

from flask import url_for
from playhouse.test_utils import count_queries

from app import instance_keys, app as realapp
from auth.auth_context_type import ValidatedAuthContext
from data import model
from data.database import Repository
from data.registry_model import registry_model
from endpoints.test.shared import conduct_call
from image.docker.schema1 import DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE
from util.security.registry_jwt import generate_bearer_token, build_context_and_subject
from test.fixtures import *  # noqa: F401, F403


BUSYBOX_MANIFEST_JSON = r"""{
   "schemaVersion": 1,
   "name": "library/busybox",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:5cc84ad355aaa64f46ea9c7bbcc319a9d808ab15088a27209c9e70ef86e5a2aa"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"sh\"],\"Image\":\"sha256:da658412c37aa24e561eb7e16c61bc82a9711340d8fb5cf1a8f39d8e96d7f723\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":null},\"container\":\"a0007fa726185ffbcb68e90f8edabedd79a08949f32f4f0bcc6e5fed713a72c8\",\"container_config\":{\"Hostname\":\"a0007fa72618\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"sh\\\"]\"],\"Image\":\"sha256:da658412c37aa24e561eb7e16c61bc82a9711340d8fb5cf1a8f39d8e96d7f723\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2021-12-30T19:19:41.006954958Z\",\"docker_version\":\"20.10.7\",\"id\":\"5ab5e1c8a2f040cd0b95f123c82a0853c87e24d278c337666d9119e2cb933fca\",\"os\":\"linux\",\"parent\":\"fb161ec7bbd38b27e660e76a08f3e57c458b94e3586ee7667405e1695a15f792\",\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"fb161ec7bbd38b27e660e76a08f3e57c458b94e3586ee7667405e1695a15f792\",\"created\":\"2021-12-30T19:19:40.833034683Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:6db446a57cbd2b7f4cfde1f280177b458390ed5a6d1b54c6169522bc2c4d838e in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "LKBE:JGAL:FWCB:NZB4:6YRQ:EKM3:VRLP:WR5K:5ZEY:2Z7D:MORV:GPWY",
               "kty": "EC",
               "x": "NXNObrhsZMN6yF22HhK04KRU1NucufpJUVgH8dNlu5w",
               "y": "xkwdVwwMh88f0ubiRFdy3ewgpsiw55LAijX-IecoVLQ"
            },
            "alg": "ES256"
         },
         "signature": "PTCOkbWvxwJIiO0Ig9icuhMJbXUxdTQKRu7qWd3k1WKdStSLEj0ETetTcIe8eYx_2oWUCWZX5AptZ0dNFSKimA",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjIwODcsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyMi0wMi0wMVQwOToyODowOVoifQ"
      }
   ]
}"""  # noqa: E501


def _get_auth_headers(subject, context, repository):
    access = [
        {
            "type": "repository",
            "name": repository,
            "actions": ["pull"],
        }
    ]
    token = generate_bearer_token(
        realapp.config["SERVER_HOSTNAME"],
        subject,
        context,
        access,
        600,
        instance_keys,
    )
    return {
        "Authorization": "Bearer %s" % token.decode("ascii"),
    }


_sha = "sha256:b69959407d21e8a062e0416bf13405bb2b71ed7a84dde4158ebafacfa06f5578"


@pytest.mark.parametrize(
    "view_name,manifest_ref",
    [("v2.fetch_manifest_by_tagname", "latest"), ("v2.fetch_manifest_by_digest", _sha)],
)
class TestManifestPullThroughStorage:
    orgname = "cache-library"
    registry = "docker.io/library"
    config = None
    org = None
    ctx = None
    sub = None

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, subject = build_context_and_subject(ValidatedAuthContext(user=self.user))
        self.ctx = context
        self.sub = subject

        if self.org is None:
            self.org = model.organization.create_organization(
                self.orgname, "{self.orgname}@devtable.com", self.user
            )
            self.org.save()
            self.config = model.proxy_cache.create_proxy_cache_config(
                org_name=self.orgname,
                upstream_registry=self.registry,
                staleness_period_s=3600,
            )

    def test_creates_repo_on_first_pull(self, view_name, manifest_ref):
        image = "busybox"
        repo = f"{self.orgname}/{image}"
        params = {
            "repository": repo,
            "manifest_ref": manifest_ref,
        }

        proxy_mock = MagicMock()
        proxy_mock.manifest_exists.return_value = {"status": 200}
        proxy_mock.get_manifest.return_value = {
            "status": 200,
            "response": BUSYBOX_MANIFEST_JSON,
            "headers": {"content-type": DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE},
        }

        with patch(
            "data.registry_model.registry_proxy_model.Proxy", MagicMock(return_value=proxy_mock)
        ):
            conduct_call(
                self.client,
                view_name,
                url_for,
                "GET",
                params,
                expected_code=200,
                headers=_get_auth_headers(self.sub, self.ctx, repo),
            )
        repo = model.repository.get_repository(self.orgname, image)
        assert repo is not None
        assert repo.visibility.name == "private"

    def test_does_not_create_repo_when_upstream_repo_does_not_exist(self, view_name, manifest_ref):
        image = "busybox"
        repo = f"{self.orgname}/{image}"
        params = {
            "repository": repo,
            "manifest_ref": manifest_ref,
        }
        proxy_mock = MagicMock()
        proxy_mock.manifest_exists.return_value = {"status": 404}
        proxy_mock.get_manifest.return_value = {"status": 404}

        with patch(
            "data.registry_model.registry_proxy_model.Proxy", MagicMock(return_value=proxy_mock)
        ):
            conduct_call(
                self.client,
                view_name,
                url_for,
                "GET",
                params,
                expected_code=404,
                headers=_get_auth_headers(self.sub, self.ctx, repo),
            )
        count = Repository.filter(
            Repository.name == image, Repository.namespace_user == self.org.id
        ).count()
        assert count == 0

    def test_does_not_create_repo_when_already_exists(self, view_name, manifest_ref):
        image = "busybox"
        repo = f"{self.orgname}/{image}"
        params = {
            "repository": repo,
            "manifest_ref": manifest_ref,
        }
        r = model.repository.create_repository(self.orgname, image, self.user)
        assert r is not None

        proxy_mock = MagicMock()
        proxy_mock.manifest_exists.return_value = {"status": 200}
        proxy_mock.get_manifest.return_value = {
            "status": 200,
            "response": BUSYBOX_MANIFEST_JSON,
            "headers": {"content-type": DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE},
        }

        with patch(
            "data.registry_model.registry_proxy_model.Proxy", MagicMock(return_value=proxy_mock)
        ):
            conduct_call(
                self.client,
                view_name,
                url_for,
                "GET",
                params,
                expected_code=200,
                headers=_get_auth_headers(self.sub, self.ctx, repo),
            )

        count = Repository.filter(
            Repository.name == image, Repository.namespace_user == self.org.id
        ).count()
        assert count == 1

    def test_caches_manifest_on_first_pull(self, view_name, manifest_ref):
        image = "busybox"
        repo = f"{self.orgname}/{image}"
        params = {
            "repository": repo,
            "manifest_ref": manifest_ref,
        }

        proxy_mock = MagicMock()
        proxy_mock.manifest_exists.return_value = {"status": 200}
        proxy_mock.get_manifest.return_value = {
            "status": 200,
            "response": BUSYBOX_MANIFEST_JSON,
            "headers": {"content-type": DOCKER_SCHEMA1_MANIFEST_CONTENT_TYPE},
        }

        with patch(
            "data.registry_model.registry_proxy_model.Proxy", MagicMock(return_value=proxy_mock)
        ):
            conduct_call(
                self.client,
                view_name,
                url_for,
                "GET",
                params,
                expected_code=200,
                headers=_get_auth_headers(self.sub, self.ctx, repo),
            )

        repository_ref = registry_model.lookup_repository(self.orgname, image)
        assert repository_ref is not None
        if "digest" in view_name:
            pytest.skip("skipping check for tags")

        tag = registry_model.get_repo_tag(repository_ref, params["manifest_ref"])
        assert tag is not None
        manifest = registry_model.get_manifest_for_tag(tag)
        assert manifest is not None

    def test_does_not_pull_from_upstream_when_manifest_is_cached(self, view_name, manifest_ref):
        pass


@pytest.mark.e2e
class TestManifestPullThroughProxyDockerHub(unittest.TestCase):
    org = "cache"
    org2 = "cache-library"
    registry = "docker.io"
    repository = f"{org}/library/postgres"
    repository2 = f"{org2}/postgres"
    tag = "14"
    ctx = None
    sub = None

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, subject = build_context_and_subject(ValidatedAuthContext(user=self.user))
        self.ctx = context
        self.sub = subject

        try:
            model.organization.get(self.org)
        except Exception:
            org = model.organization.create_organization(self.org, "cache@devtable.com", self.user)
            org.save()

        try:
            model.organization.get(self.org2)
        except Exception:
            org = model.organization.create_organization(
                self.org2,
                "cache-library@devtable.com",
                self.user,
            )
            org.save()

        try:
            model.proxy_cache.get_proxy_cache_config_for_org(self.org)
        except Exception:
            model.proxy_cache.create_proxy_cache_config(
                org_name=self.org,
                upstream_registry=self.registry,
            )

        try:
            model.proxy_cache.get_proxy_cache_config_for_org(self.org2)
        except Exception:
            model.proxy_cache.create_proxy_cache_config(
                org_name=self.org2,
                upstream_registry=self.registry + "/library",
            )

    def _get_auth_headers(self, repository):
        access = [
            {
                "type": "repository",
                "name": repository,
                "actions": ["pull"],
            }
        ]
        token = generate_bearer_token(
            realapp.config["SERVER_HOSTNAME"],
            self.sub,
            self.ctx,
            access,
            600,
            instance_keys,
        )
        return {
            "Authorization": "Bearer %s" % token.decode("ascii"),
        }

    def test_pull_proxy_whole_dockerhub(self):
        params = {
            "repository": self.repository,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self._get_auth_headers(self.repository),
        )

    def test_pull_proxy_single_namespace_dockerhub(self):
        params = {
            "repository": self.repository2,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self._get_auth_headers(self.repository2),
        )

    def test_pull_proxy_whole_dockerhub_404(self):
        params = {
            "repository": self.repository,
            "manifest_ref": "666",
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=404,
            headers=self._get_auth_headers(self.repository),
        )

    def test_pull_from_dockerhub_by_digest(self):
        digest = "sha256:f329d076a8806c0ce014ce5e554ca70f4ae9407a16bb03baa7fef287ee6371f1"
        params = {
            "repository": self.repository,
            "manifest_ref": digest,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_digest",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self._get_auth_headers(self.repository),
        )

    def test_check_manifest_exists_from_dockerhub_by_tag(self):
        params = {
            "repository": self.repository,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "HEAD",
            params,
            expected_code=200,
            headers=self._get_auth_headers(self.repository),
        )

    def test_check_manifest_exists_from_dockerhub_by_tag_404(self):
        params = {
            "repository": self.repository,
            "manifest_ref": "666",
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "HEAD",
            params,
            expected_code=404,
            headers=self._get_auth_headers(self.repository),
        )


@pytest.mark.e2e
class TestManifestPullThroughProxy(unittest.TestCase):
    org = "cache"
    org2 = "cache-library"
    registry = "docker.io"
    repository = f"{org}/library/postgres"
    repository2 = f"{org2}/postgres"
    tag = "14"
    ctx = None
    sub = None

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, sub = build_context_and_subject(ValidatedAuthContext(user=self.user))
        self.ctx = context
        self.sub = sub

        try:
            model.organization.get(self.org)
        except Exception:
            org = model.organization.create_organization(self.org, "cache@devtable.com", self.user)
            org.save()

        try:
            model.organization.get(self.org2)
        except Exception:
            org = model.organization.create_organization(
                self.org2,
                "cache-library@devtable.com",
                self.user,
            )
            org.save()

        try:
            model.proxy_cache.get_proxy_cache_config_for_org(self.org)
        except Exception:
            model.proxy_cache.create_proxy_cache_config(
                org_name=self.org,
                upstream_registry=self.registry,
                staleness_period_s=3600,
            )

        try:
            model.proxy_cache.get_proxy_cache_config_for_org(self.org2)
        except Exception:
            model.proxy_cache.create_proxy_cache_config(
                org_name=self.org2,
                upstream_registry=self.registry + "/library",
                staleness_period_s=3600,
            )

    def _get_auth_headers(self, repository):
        access = [
            {
                "type": "repository",
                "name": repository,
                "actions": ["pull"],
            }
        ]
        token = generate_bearer_token(
            realapp.config["SERVER_HOSTNAME"],
            self.sub,
            self.ctx,
            access,
            600,
            instance_keys,
        )
        return {
            "Authorization": "Bearer %s" % token.decode("ascii"),
        }

    def test_pull_proxy_whole_registry(self):
        params = {
            "repository": self.repository,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository),
        )

    def test_pull_proxy_single_namespace(self):
        params = {
            "repository": self.repository2,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository2),
        )

    def test_pull_proxy_whole_registry_404(self):
        params = {
            "repository": self.repository,
            "manifest_ref": "666",
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=404,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository),
        )

    def test_pull_by_digest(self):
        digest = "sha256:f329d076a8806c0ce014ce5e554ca70f4ae9407a16bb03baa7fef287ee6371f1"
        params = {
            "repository": self.repository,
            "manifest_ref": digest,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_digest",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository),
        )

    def test_check_manifest_exists_by_tag(self):
        params = {
            "repository": self.repository,
            "manifest_ref": self.tag,
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "HEAD",
            params,
            expected_code=200,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository),
        )

    def test_check_manifest_exists_by_tag_404(self):
        params = {
            "repository": self.repository,
            "manifest_ref": "666",
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "HEAD",
            params,
            expected_code=404,
            headers=_get_auth_headers(self.sub, self.ctx, self.repository),
        )


def test_e2e_query_count_manifest_norewrite(client, app):
    repo_ref = registry_model.lookup_repository("devtable", "simple")
    tag = registry_model.get_repo_tag(repo_ref, "latest")
    manifest = registry_model.get_manifest_for_tag(tag)

    params = {
        "repository": "devtable/simple",
        "manifest_ref": manifest.digest,
    }

    user = model.user.get_user("devtable")
    access = [
        {
            "type": "repository",
            "name": "devtable/simple",
            "actions": ["pull", "push"],
        }
    ]

    context, subject = build_context_and_subject(ValidatedAuthContext(user=user))
    token = generate_bearer_token(
        realapp.config["SERVER_HOSTNAME"], subject, context, access, 600, instance_keys
    )

    headers = {
        "Authorization": "Bearer %s" % token.decode("ascii"),
    }

    # Conduct a call to prime the instance key and other caches.
    conduct_call(
        client,
        "v2.write_manifest_by_digest",
        url_for,
        "PUT",
        params,
        expected_code=201,
        headers=headers,
        raw_body=manifest.internal_manifest_bytes.as_encoded_str(),
    )

    timecode = time.time()

    def get_time():
        return timecode + 10

    with patch("time.time", get_time):
        # Necessary in order to have the tag updates not occur in the same second, which is the
        # granularity supported currently.
        with count_queries() as counter:
            conduct_call(
                client,
                "v2.write_manifest_by_digest",
                url_for,
                "PUT",
                params,
                expected_code=201,
                headers=headers,
                raw_body=manifest.internal_manifest_bytes.as_encoded_str(),
            )

        assert counter.count <= 27
