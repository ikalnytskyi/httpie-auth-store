"""HTTPie Credential Store Auth Plugin."""

import requests
import httpie.plugins

from ._auth import get_auth
from ._cred import get_credential_store


class CredentialStoreAuthPlugin(httpie.plugins.AuthPlugin):
    """Attach authentication to ongoing HTTP request.

    Usage::

        $ http -A credential-store http://example.com/v1/resource
        $ http -A credential-store -a ihor http://example.com/v1/resource
    """

    name = "credential-store"
    description = "Retrieve and set auth information based on URL."

    auth_type = (
        "credential-store"  # use plugin by passing '-A credential-store'
    )
    auth_require = False  # do not require passing '-a' argument
    auth_parse = False  # do not parse '-a' content

    def get_auth(self, username=None, password=None):
        credential_id = self.raw_auth

        class CredentialStoreAuth(requests.auth.AuthBase):
            def __call__(self, request):
                store = get_credential_store("credentials.json")
                auth = store.lookup(request.url, credential_id)
                set_auth = get_auth(auth)
                return set_auth(request)

        return CredentialStoreAuth()


class CredsAuthPlugin(CredentialStoreAuthPlugin):
    """Nothing more but a convenient alias."""

    auth_type = "creds"  # use plugin by passing '-A creds'
