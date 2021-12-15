import unittest
import pytest
import time

from mock import patch

from flask import url_for
from playhouse.test_utils import count_queries

from app import instance_keys, app as realapp
from auth.auth_context_type import ValidatedAuthContext
from data import model
from data.registry_model import registry_model
from endpoints.test.shared import conduct_call
from util.security.registry_jwt import generate_bearer_token, build_context_and_subject
from test.fixtures import *


@pytest.mark.e2e
class TestManifestPullThroughProxy(unittest.TestCase):
    org = "cache"
    org2 = "cache-library"
    registry = "docker.io"
    repository = f"{org}/library/postgres"
    repository2 = f"{org2}/postgres"
    tag = "14"
    context = None
    subject = None

    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})
        app.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, subject = build_context_and_subject(ValidatedAuthContext(user=self.user))
        self.context = context
        self.subject = subject

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
            org.stripe_id = TEST_STRIPE_ID
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
            self.subject,
            self.context,
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
    context = None
    subject = None

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        realapp.config.update({"FEATURE_PROXY_CACHE": True})

        self.user = model.user.get_user("devtable")
        context, subject = build_context_and_subject(ValidatedAuthContext(user=self.user))
        self.context = context
        self.subject = subject

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
            self.subject,
            self.context,
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
