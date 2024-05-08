"""HTTPie Credential Store Auth Plugin."""

import httpie.plugins
import requests

from ._store import get_credential_store


class StoreAuthPlugin(httpie.plugins.AuthPlugin):
    """Attach authentication to ongoing HTTP request.

    Usage::

        $ http -A credential-store http://example.com/v1/resource
        $ http -A credential-store -a ihor http://example.com/v1/resource
    """

    name = "HTTPie Credential Store"
    description = "Retrieve & attach authentication to ongoing HTTP request."

    auth_type = "store"  # use plugin by passing '-A store'
    auth_require = False  # do not require passing '-a' argument
    auth_parse = False  # do not parse '-a' content

    def get_auth(self, username=None, password=None):
        _ = username
        _ = password
        credential_id = self.raw_auth

        class CredentialStoreAuth(requests.auth.AuthBase):
            def __call__(self, request):
                store = get_credential_store("credentials.json")
                auth = store.get_auth_for(request.url, credential_id)
                return auth(request)

        return CredentialStoreAuth()


class CredentialStoreAuthPlugin(StoreAuthPlugin):
    """DEPRECATED: invoke 'store' authentication via '-A credential-store'."""

    auth_type = "credential-store"


class CredsAuthPlugin(CredentialStoreAuthPlugin):
    """DEPRECATED: invoke 'store' authentication via '-A creds'."""

    auth_type = "creds"
