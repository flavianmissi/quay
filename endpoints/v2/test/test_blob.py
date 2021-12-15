import json
import unittest
import hashlib
import pytest

from mock import patch
from flask import url_for
from playhouse.test_utils import assert_query_count

from app import instance_keys, app as realapp
from auth.auth_context_type import ValidatedAuthContext
from data import model
from data.cache import InMemoryDataModelCache
from data.cache.test.test_cache import TEST_CACHE_CONFIG
from data.database import ImageStorageLocation
from endpoints.test.shared import conduct_call
from util.security.registry_jwt import generate_bearer_token, build_context_and_subject
from test.fixtures import *


@pytest.mark.e2e
class TestBlobPullThroughProxy(unittest.TestCase):
    org = "cache"
    registry = "docker.io"
    repository = f"{org}/library/postgres"
    tag = "14"
    _blob_digest = None

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, subject = build_context_and_subject(ValidatedAuthContext(user=self.user))
        access = [
            {
                "type": "repository",
                "name": self.repository,
                "actions": ["pull"],
            }
        ]
        token = generate_bearer_token(
            realapp.config["SERVER_HOSTNAME"], subject, context, access, 600, instance_keys
        )
        self.headers = {
            "Authorization": f"Bearer {token.decode('ascii')}",
        }

        try:
            model.organization.get(self.org)
        except Exception:
            org = model.organization.create_organization(self.org, "cache@devtable.com", self.user)
            org.save()

        try:
            model.proxy_cache.get_proxy_cache_config_for_org(self.org)
        except Exception:
            model.proxy_cache.create_proxy_cache_config(
                org_name=self.org,
                upstream_registry=self.registry,
                staleness_period_s=3600,
            )

    def _get_blob_digest(self) -> str:
        if self._blob_digest is not None:
            return self._blob_digest

        params = {
            "repository": self.repository,
            "manifest_ref": self.tag,
        }
        resp = conduct_call(
            self.client,
            "v2.fetch_manifest_by_tagname",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self.headers,
        )
        manifest = json.loads(resp.response[0])
        self._blob_digest = manifest["fsLayers"][0]["blobSum"]
        return self._blob_digest

    def test_pull_from_dockerhub(self):
        params = {
            "repository": self.repository,
            "digest": self._get_blob_digest(),
        }
        conduct_call(
            self.client,
            "v2.download_blob",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self.headers,
        )

    def test_pull_from_dockerhub_404(self):
        digest = "sha256:" + hashlib.sha256(b"a").hexdigest()
        params = {
            "repository": self.repository,
            "digest": digest,
        }
        conduct_call(
            self.client,
            "v2.download_blob",
            url_for,
            "GET",
            params,
            expected_code=404,
            headers=self.headers,
        )

    def test_check_blob_exists_from_dockerhub(self):
        params = {
            "repository": self.repository,
            "digest": self._get_blob_digest(),
        }
        conduct_call(
            self.client,
            "v2.check_blob_exists",
            url_for,
            "HEAD",
            params,
            expected_code=200,
            headers=self.headers,
        )

    def test_check_blob_exists_from_dockerhub_404(self):
        digest = "sha256:" + hashlib.sha256(b"a").hexdigest()
        params = {
            "repository": self.repository,
            "digest": digest,
        }
        conduct_call(
            self.client,
            "v2.check_blob_exists",
            url_for,
            "HEAD",
            params,
            expected_code=404,
            headers=self.headers,
        )


@pytest.mark.parametrize(
    "method, endpoint",
    [
        ("GET", "download_blob"),
        ("HEAD", "check_blob_exists"),
    ],
)
def test_blob_caching(method, endpoint, client, app):
    digest = "sha256:" + hashlib.sha256(b"a").hexdigest()
    location = ImageStorageLocation.get(name="local_us")
    model.blob.store_blob_record_and_temp_link("devtable", "simple", digest, location, 1, 10000000)

    params = {
        "repository": "devtable/simple",
        "digest": digest,
    }

    user = model.user.get_user("devtable")

    access = [
        {
            "type": "repository",
            "name": "devtable/simple",
            "actions": ["pull"],
        }
    ]

    context, subject = build_context_and_subject(ValidatedAuthContext(user=user))
    token = generate_bearer_token(
        realapp.config["SERVER_HOSTNAME"], subject, context, access, 600, instance_keys
    )

    headers = {
        "Authorization": "Bearer %s" % token.decode("ascii"),
    }

    # Run without caching to make sure the request works. This also preloads some of
    # our global model caches.
    conduct_call(
        client, "v2." + endpoint, url_for, method, params, expected_code=200, headers=headers
    )
    with patch("endpoints.v2.blob.model_cache", InMemoryDataModelCache(TEST_CACHE_CONFIG)):
        # First request should make a DB query to retrieve the blob.
        conduct_call(
            client, "v2." + endpoint, url_for, method, params, expected_code=200, headers=headers
        )

        # Subsequent requests should use the cached blob.
        with assert_query_count(0):
            conduct_call(
                client,
                "v2." + endpoint,
                url_for,
                method,
                params,
                expected_code=200,
                headers=headers,
            )


@pytest.mark.parametrize(
    "mount_digest, source_repo, username, include_from_param, expected_code",
    [
        # Unknown blob.
        ("sha256:unknown", "devtable/simple", "devtable", True, 202),
        ("sha256:unknown", "devtable/simple", "devtable", False, 202),
        # Blob not in repo.
        ("sha256:" + hashlib.sha256(b"a").hexdigest(), "devtable/complex", "devtable", True, 202),
        ("sha256:" + hashlib.sha256(b"a").hexdigest(), "devtable/complex", "devtable", False, 202),
        # # Blob in repo.
        ("sha256:" + hashlib.sha256(b"b").hexdigest(), "devtable/complex", "devtable", True, 201),
        ("sha256:" + hashlib.sha256(b"b").hexdigest(), "devtable/complex", "devtable", False, 202),
        # # No access to repo.
        ("sha256:" + hashlib.sha256(b"b").hexdigest(), "devtable/complex", "public", True, 202),
        ("sha256:" + hashlib.sha256(b"b").hexdigest(), "devtable/complex", "public", False, 202),
        # # Public repo.
        ("sha256:" + hashlib.sha256(b"c").hexdigest(), "public/publicrepo", "devtable", True, 201),
        ("sha256:" + hashlib.sha256(b"c").hexdigest(), "public/publicrepo", "devtable", False, 202),
    ],
)
def test_blob_mounting(
    mount_digest, source_repo, username, include_from_param, expected_code, client, app
):
    location = ImageStorageLocation.get(name="local_us")

    # Store and link some blobs.
    digest = "sha256:" + hashlib.sha256(b"a").hexdigest()
    model.blob.store_blob_record_and_temp_link("devtable", "simple", digest, location, 1, 10000000)

    digest = "sha256:" + hashlib.sha256(b"b").hexdigest()
    model.blob.store_blob_record_and_temp_link("devtable", "complex", digest, location, 1, 10000000)

    digest = "sha256:" + hashlib.sha256(b"c").hexdigest()
    model.blob.store_blob_record_and_temp_link(
        "public", "publicrepo", digest, location, 1, 10000000
    )

    params = {
        "repository": "devtable/building",
        "mount": mount_digest,
    }
    if include_from_param:
        params["from"] = source_repo

    user = model.user.get_user(username)
    access = [
        {
            "type": "repository",
            "name": "devtable/building",
            "actions": ["pull", "push"],
        }
    ]

    if source_repo.find(username) == 0:
        access.append(
            {
                "type": "repository",
                "name": source_repo,
                "actions": ["pull"],
            }
        )

    context, subject = build_context_and_subject(ValidatedAuthContext(user=user))
    token = generate_bearer_token(
        realapp.config["SERVER_HOSTNAME"], subject, context, access, 600, instance_keys
    )

    headers = {
        "Authorization": "Bearer %s" % token.decode("ascii"),
    }

    conduct_call(
        client,
        "v2.start_blob_upload",
        url_for,
        "POST",
        params,
        expected_code=expected_code,
        headers=headers,
    )

    repository = model.repository.get_repository("devtable", "building")

    if expected_code == 201:
        # Ensure the blob now exists under the repo.
        assert model.oci.blob.get_repository_blob_by_digest(repository, mount_digest)
    else:
        assert model.oci.blob.get_repository_blob_by_digest(repository, mount_digest) is None


def test_blob_upload_offset(client, app):
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

    # Create a blob upload request.
    params = {
        "repository": "devtable/simple",
    }
    response = conduct_call(
        client, "v2.start_blob_upload", url_for, "POST", params, expected_code=202, headers=headers
    )

    upload_uuid = response.headers["Docker-Upload-UUID"]

    # Attempt to start an upload past index zero.
    params = {
        "repository": "devtable/simple",
        "upload_uuid": upload_uuid,
    }

    headers = {
        "Authorization": "Bearer %s" % token.decode("ascii"),
        "Content-Range": "13-50",
    }

    conduct_call(
        client,
        "v2.upload_chunk",
        url_for,
        "PATCH",
        params,
        expected_code=416,
        headers=headers,
        body="something",
    )
