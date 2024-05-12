"""HTTPie Credential Store Auth Plugin."""

import typing as t

import httpie.plugins
import httpie.plugins.registry
import requests
import requests.auth

from ._auth import HeaderAuthPlugin
from ._store import get_credential_store


class StoreAuthPlugin(httpie.plugins.AuthPlugin):
    """Sign requests using a retrieved authentication from the store.

    Usage::

        $ http -A store http://example.com/v1/resource
        $ http -A store -a <binding-id> http://example.com/v1/resource
    """

    name = "HTTPie Credential Store"
    description = "Sign requests using a retrieved authentication from the store"

    auth_type = "store"
    auth_require = False
    auth_parse = False

    def get_auth(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> requests.auth.AuthBase:
        _ = username
        _ = password

        binding_id = self.raw_auth
        store = get_credential_store("credentials.json")

        class CredentialStoreAuth(requests.auth.AuthBase):
            def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
                # The credentials store plugin provides extended authentication
                # capabilities, and therefore requires registering extra
                # authentication plugins.
                httpie.plugins.registry.plugin_manager.register(HeaderAuthPlugin)

                try:
                    request_auth = store.get_auth_for(request.url, binding_id)
                    request = request_auth(request)
                finally:
                    httpie.plugins.registry.plugin_manager.unregister(HeaderAuthPlugin)
                return request

        return CredentialStoreAuth()


class CredentialStoreAuthPlugin(StoreAuthPlugin):
    """DEPRECATED: invoke 'store' authentication via '-A credential-store'."""

    auth_type = "credential-store"


class CredsAuthPlugin(CredentialStoreAuthPlugin):
    """DEPRECATED: invoke 'store' authentication via '-A creds'."""

    auth_type = "creds"
