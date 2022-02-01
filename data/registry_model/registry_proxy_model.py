from __future__ import annotations

import features
from app import app, storage
from data.database import db_disallow_replica_use, db_transaction
from data.model import oci
from data.model.repository import get_repository, create_repository
from data.model.proxy_cache import get_proxy_cache_config_for_org
from data.registry_model.registry_oci_model import OCIModel
from data.registry_model.datatypes import Manifest, Tag, RepositoryReference
from image.shared import ManifestException
from image.shared.schemas import parse_manifest_from_bytes
from image.docker.schema1 import DockerSchema1Manifest
from proxy import Proxy
from util.bytes import Bytes


class ProxyModel(OCIModel):

    def __init__(self, namespace_name, repo_name, manifest_ref, media_type, user):
        super().__init__()
        self._config = get_proxy_cache_config_for_org(namespace_name)
        self._media_type = media_type
        self._manifest_ref = manifest_ref
        self._user = user

        # when Quay is set up to proxy a whole upstream registry, the
        # upstream_registry_namespace for the proxy cache config will be empty.
        # the given repo then is expected to include both, the upstream namespace
        # and repo. Quay will treat it as a nested repo.
        target_ns = self._config.upstream_registry_namespace
        if target_ns != "" and target_ns is not None:
            repo_name = f"{target_ns}/{repo_name}"

        self._proxy = Proxy(self._config, repo_name)

    def lookup_repository(self, namespace_name, repo_name, kind_filter=None):
        """
        Looks up and returns a reference to the repository with the given namespace and name, or
        None if none.
        """
        repo = get_repository(namespace_name, repo_name)
        cached = repo is not None
        exists_upstream = self._proxy.manifest_exists(self._manifest_ref)["status"] == 200

        # TODO: consider staleness period
        if not cached and exists_upstream:
            repo = create_repository(namespace_name, repo_name, self._user)
            # TODO: handle repo creation error (repo is None)

        if not exists_upstream:
            return None

        return RepositoryReference.for_repo_obj(
            repo,
            namespace_name,
            repo_name,
            repo.namespace_user.stripe_id is None if repo else None,
            state=repo.state if repo is not None else None,
        )

    # TODO: override with proxy logic
    # def get_manifest_for_tag(self, tag):
    #     """
    #     Returns the manifest associated with the given tag.
    #     """

    def lookup_manifest_by_digest(
        self,
        repository_ref,
        manifest_digest,
        allow_dead=False,
        require_available=False,
    ):
        """
        Looks up the manifest with the given digest under the given repository and returns it or
        None if none.

        If a manifest with the digest does not exist, fetches the manifest upstream
        and creates it with a temp tag.
        """
        manifest = super().lookup_manifest_by_digest(
            repository_ref, manifest_digest, allow_dead, require_available
        )
        # TODO: verify staleness period before returning manifest,
        # and if not within period, fetch and cache updated version upstream

        if manifest is not None:
            return manifest

        exists_upstream = self._proxy.manifest_exists(self._manifest_ref)["status"] == 200
        if not exists_upstream:
            return None

        resp = self._proxy.get_manifest(manifest_digest, self._media_type)
        upstream_repo_name = repository_ref.name
        upstream_namespace = self._config.upstream_registry_namespace
        if upstream_namespace is None:
            # TODO: we need to do this in a better way
            parts = repository_ref.name.split("/")
            upstream_namespace = parts[0]
            upstream_repo_name = parts[1]

        # TODO: do we need the compatibility check from v2._parse_manifest?
        content_type = resp["headers"]["content-type"]
        mbytes = Bytes.for_string_or_unicode(resp["response"])
        manifest = parse_manifest_from_bytes(mbytes, content_type, sparse_manifest_support=True)
        valid = self._validate_schema1_manifest(upstream_namespace, upstream_repo_name, manifest)
        if not valid:
            return None

        expiration = self._config.staleness_period_s or None
        return self.create_manifest_with_temp_tag(repository_ref, manifest, expiration, storage)

    def get_repo_tag(self, repository_ref, tag_name):
        """
        Returns the latest, *active* tag found in the repository, with the matching
        name or None if none.

        If both manifest and tag don't exist, fetches the manifest with the tag
        from upstream, and creates them both.
        """
        tag = super().get_repo_tag(repository_ref, tag_name)
        if tag is not None:
            return tag

        resp = self._proxy.get_manifest(tag_name, self._media_type)
        upstream_repo_name = repository_ref.name
        upstream_namespace = self._config.upstream_registry_namespace
        if upstream_namespace is None:
            # TODO: we need to do this in a better way
            parts = repository_ref.name.split("/")
            upstream_namespace = parts[0]
            upstream_repo_name = parts[1]

        # TODO: do we need the compatibility check from v2._parse_manifest?
        content_type = resp["headers"]["content-type"]
        mbytes = Bytes.for_string_or_unicode(resp["response"])
        manifest = parse_manifest_from_bytes(mbytes, content_type, sparse_manifest_support=True)
        valid = self._validate_schema1_manifest(upstream_namespace, upstream_repo_name, manifest)
        if not valid:
            return None

        try:
            _, tag = self.create_manifest_and_retarget_tag(
                repository_ref, manifest, tag_name, storage
            )
            return tag
        except (oci.manifest.CreateManifestException, oci.tag.RetargetTagException) as e:
            return None

        return None

    def create_manifest_and_retarget_tag(
        self, repository_ref, manifest_interface_instance, tag_name, storage, raise_on_error=False
    ) -> tuple[Manifest | None, Tag | None]:
        """
        Creates a manifest in a repository, adding all of the necessary data in the model.

        The `manifest_interface_instance` parameter must be an instance of the manifest
        interface as returned by the image/docker or image/oci package.

        Returns a reference to the (created manifest, tag) or (None, None) on error.
        """
        manifest = manifest_interface_instance
        with db_disallow_replica_use():
            with db_transaction():
                db_manifest = oci.manifest.create_manifest(repository_ref.id, manifest)
                if db_manifest is None:
                    return (None, None)


                # 0 is equivalent to no expiration - if we get 0 as staleness period,
                # we set the tag expiration to None.
                expiration = self._config.staleness_period_s or None
                tag = oci.tag.retarget_tag(
                    tag_name,
                    db_manifest,
                    raise_on_error=raise_on_error,
                    expiration_seconds=expiration,
                )
                if tag is None:
                    return (None, None)

                wrapped_manifest = Manifest.for_manifest(db_manifest, self._legacy_image_id_handler)
                wrapped_tag = Tag.for_tag(
                    tag, self._legacy_image_id_handler, manifest_row=db_manifest
                )

                if not manifest.is_manifest_list:
                    return wrapped_manifest, wrapped_tag

                manifests_to_connect = []
                for child in manifest.child_manifests(None):
                    m = oci.manifest.create_manifest(repository_ref.id, child)
                    manifests_to_connect.append(m)

                oci.manifest.connect_manifests(manifests_to_connect, db_manifest, repository_ref.id)

                return wrapped_manifest, wrapped_tag

    def create_manifest_with_temp_tag(
        self, repository_ref, manifest_interface_instance, expiration_sec, storage
    ):
        manifest = manifest_interface_instance
        with db_disallow_replica_use():
            with db_transaction():
                db_manifest = oci.manifest.create_manifest(repository_ref.id, manifest)
                if db_manifest is None:
                    return None

                oci.tag.create_temporary_tag_if_necessary(db_manifest, expiration_sec)

                wrapped_manifest = Manifest.for_manifest(db_manifest, self._legacy_image_id_handler)

                if not manifest.is_manifest_list:
                    return wrapped_manifest

                manifests_to_connect = []
                for child in manifest.child_manifests(None):
                    m = oci.manifest.create_manifest(repository_ref.id, child)
                    manifests_to_connect.append(m)

                oci.manifest.connect_manifests(manifests_to_connect, db_manifest, repository_ref.id)
                for db_manifest in manifests_to_connect:
                    oci.tag.create_temporary_tag_if_necessary(db_manifest, expiration_sec)

                return wrapped_manifest

    def _validate_schema1_manifest(
        self, namespace: str, repo: str, manifest: DockerSchema1Manifest
    ) -> bool:
        if manifest.schema_version != 1:
            return True

        if (
            manifest.namespace == ""
            and features.LIBRARY_SUPPORT
            and namespace == app.config["LIBRARY_NAMESPACE"]
        ):
            pass
        elif manifest.namespace != namespace:
            return False

        if manifest.repo_name != repo:
            return False

        return True

    # TODO: probably needs to override all this active tag stuff. double check
    # def lookup_cached_active_repository_tags(
    #     self, model_cache, repository_ref, start_pagination_id, limit
    # ):

    # def lookup_active_repository_tags(self, repository_ref, start_pagination_id, limit):

    # def list_all_active_repository_tags(self, repository_ref):

    # TODO: probably need to override - proxied images don't support tag expiration
    # def has_expired_tag(self, repository_ref, tag_name):

    # TODO: override, proxied images won't support deletion?
    # def delete_tag(self, repository_ref, tag_name):

    # def delete_tags_for_manifest(self, manifest):

    # TODO: override - need to disable this for proxied images
    # def change_repository_tag_expiration(self, tag, expiration_date):

    # TODO: what does local mean here?
    # def get_manifest_local_blobs(self, manifest, storage, include_placements=False):

    # TODO: override and disable functionality
    # def set_tags_expiration_for_manifest(self, manifest, expiration_sec):

    # TODO: maybe override with staleness period stuff to consider?
    # def find_repository_with_garbage(self, limit_to_gc_policy_s):
