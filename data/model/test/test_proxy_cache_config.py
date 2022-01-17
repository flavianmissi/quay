from data.model import InvalidOrganizationException
from data.model.proxy_cache import *
from data.model.organization import create_organization
from data.database import ProxyCacheConfig
from test.fixtures import *


def create_org(user_name, user_email, org_name, org_email):
    user_obj = create_user_noverify(user_name, user_email)
    return create_organization(org_name, org_email, user_obj)


def test_create_proxy_cache_config_with_defaults(initialized_db):
    upstream_registry = "something here"
    org = create_org(user_name="test", user_email="test@example.com", org_name="foobar", org_email="foo@example.com")
    result = create_proxy_cache_config(org.username, upstream_registry)

    assert result.user_id.id == org.id
    assert result.upstream_registry == upstream_registry
    assert result.upstream_registry_namespace is None
    assert result.upstream_registry_username is None
    assert result.upstream_registry_password is None
    assert result.staleness_period_s == 0
    assert result.quota_enabled == 0


def test_create_proxy_cache_config_without_defaults(initialized_db):
    upstream_registry = "registry-1.docker.io"
    upstream_registry_namespace = "library"
    upstream_registry_username = "admin"
    upstream_registry_password = "password"
    staleness_period_s = 3600
    quota_enabled = True

    org = create_org(user_name="test", user_email="test@example.com", org_name="foobar", org_email="foo@example.com")
    result = create_proxy_cache_config(
        org.username,
        upstream_registry=upstream_registry,
        upstream_registry_namespace=upstream_registry_namespace,
        upstream_registry_username=upstream_registry_username,
        upstream_registry_password=upstream_registry_password,
        staleness_period_s=staleness_period_s,
        quota_enabled=quota_enabled
    )

    assert result.user_id.id == org.id
    assert result.upstream_registry == upstream_registry
    assert result.upstream_registry_namespace == upstream_registry_namespace
    assert result.upstream_registry_username == upstream_registry_username
    assert result.upstream_registry_password == upstream_registry_password
    assert result.staleness_period_s == staleness_period_s
    assert result.quota_enabled == quota_enabled


@pytest.mark.xfail(raises=InvalidOrganizationException)
def test_create_proxy_cache_config_without_org(initialized_db):
    upstream_registry = "something here"
    namespace = "something here"

    create_proxy_cache_config(namespace, upstream_registry)


def test_get_proxy_cache_config_for_org(initialized_db):
    upstream_registry = "something here"

    org = create_org(user_name="test", user_email="test@example.com", org_name="foobar", org_email="foo@example.com")
    create_proxy_cache_config(org.username, upstream_registry)
    result = get_proxy_cache_config_for_org(org.username)

    assert result.user_id.id == org.id
    assert result.upstream_registry == upstream_registry
    assert result.upstream_registry_namespace is None
    assert result.upstream_registry_username is None
    assert result.upstream_registry_password is None
    assert result.staleness_period_s == 0
    assert result.quota_enabled == 0


@pytest.mark.xfail(raises=ProxyCacheConfig.DoesNotExist)
def test_get_proxy_cache_config_for_org_without_proxy_config(initialized_db):
    test_org = "test"
    test_email = "test@example.com"

    user_obj = create_user_noverify(test_org, test_email)
    org = create_organization("foobar", "foo@example.com", user_obj)
    get_proxy_cache_config_for_org(org.username)


@pytest.mark.xfail(raises=InvalidOrganizationException)
def test_get_proxy_cache_config_for_org_without_org(initialized_db):
    namespace = "something here"
    get_proxy_cache_config_for_org(namespace)
