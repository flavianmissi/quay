from __future__ import annotations
from app import app
from data.database import ProxyCacheConfig
from data.model import InvalidOrganizationException
from data.model.proxy_cache import get_proxy_cache_config_for_org
from proxy import Proxy


class ProxyNotSupported(Exception):
    pass


def get_proxy_config(org_name: str) -> ProxyCacheConfig:
    """
    Returns a ProxyCacheConfig instance if org_name is set up as a proxy cache org.
    Raises ProxyNotSupported exception if a user, or an org not set up as proxy
    cache is given.

    Proxy cache orgs are organizations (not users) that have a ProxyCacheConfig
    object associated to them.
    """
    if not app.config.get("FEATURE_PROXY_CACHE", False):
        raise ProxyNotSupported("Proxy globally disabled.")

    try:
        config = get_proxy_cache_config_for_org(org_name)
        return config
    except (InvalidOrganizationException, ProxyCacheConfig.DoesNotExist):
        # we may end up here if `org_name` either refers to a user
        # or if the org is not set up as cache - either way proxy shouldn't work.
        raise ProxyNotSupported("Organization is invalid or not configured as proxy cache.")


# def setup_proxy(config: ProxyCacheConfig, repo: str) -> Proxy:
def setup_proxy(org_name: str, repo: str) -> (Proxy, ProxyCacheConfig):
    """
    Returns a proxy.Proxy instance set up for the given ProxyCacheConfig and repository.
    """

    config = get_proxy_config(org_name)

    # when Quay is set up to proxy a whole upstream registry, the
    # upstream_registry_namespace for the proxy cache config will be empty.
    # the given repo then is expected to include both, the upstream namespace
    # and repo. Quay will treat it as a nested repo.
    target_ns = config.upstream_registry_namespace
    if target_ns != "" and target_ns is not None:
        repo = f"{target_ns}/{repo}"

    proxy = Proxy(config, repo)
    return proxy, config
