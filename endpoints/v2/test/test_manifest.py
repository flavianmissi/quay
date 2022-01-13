import unittest
import hashlib
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
from initdb import TEST_STRIPE_ID




@pytest.mark.e2e
class TestManifestPullThroughProxy(unittest.TestCase):
    org = "cache"
    repository = f"{org}/library/postgres"
    tag = "14"

    @pytest.fixture(autouse=True)
    def setup(self, client, app):
        self.client = client
        self.app = app
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
            "Authorization": "Bearer %s" % token.decode("ascii"),
        }

        try:
            model.organization.get(self.org)
        except Exception:
            org = model.organization.create_organization(self.org, "cache@devtable.com", self.user)
            org.stripe_id = TEST_STRIPE_ID
            org.save()

    def test_pull_from_dockerhub(self):
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
            headers=self.headers,
        )

    def test_pull_from_dockerhub_404(self):
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
            headers=self.headers,
        )

    def test_pull_from_dockerhub_by_digest(self):
        params = {
            "repository": self.repository,
            "manifest_ref": "sha256:f329d076a8806c0ce014ce5e554ca70f4ae9407a16bb03baa7fef287ee6371f1",
        }
        conduct_call(
            self.client,
            "v2.fetch_manifest_by_digest",
            url_for,
            "GET",
            params,
            expected_code=200,
            headers=self.headers,
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
