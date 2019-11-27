"""Various authentication providers for python-requests."""

import collections.abc
import requests.auth

from ._keychain import get_keychain


def get_secret_value(value):
    if not isinstance(value, collections.abc.Mapping):
        return value

    keychain = get_keychain(value.pop("keychain"))
    return keychain.get(**value)


class HTTPBasicAuth(requests.auth.HTTPBasicAuth):
    """Authentication via HTTP Basic scheme."""

    def __init__(self, username, password):
        super(HTTPBasicAuth, self).__init__(
            username, get_secret_value(password)
        )


class HTTPDigestAuth(requests.auth.HTTPDigestAuth):
    """Authentication via HTTP Digest scheme."""

    def __init__(self, username, password):
        super(HTTPDigestAuth, self).__init__(
            username, get_secret_value(password)
        )


class HTTPHeaderAuth(requests.auth.AuthBase):
    """Authentication via custom HTTP header."""

    def __init__(self, name, value):
        self._header_name = name
        self._header_value = get_secret_value(value)

    def __call__(self, request):
        request.headers[self._header_name] = self._header_value
        return request


class HTTPTokenAuth(HTTPHeaderAuth):
    """Authentication via token."""

    def __init__(self, token, scheme="Bearer"):
        token = get_secret_value(token)

        super(HTTPTokenAuth, self).__init__(
            "Authorization", f"{scheme} {token}"
        )


AUTH = {
    "basic": HTTPBasicAuth,
    "digest": requests.auth.HTTPDigestAuth,
    "header": HTTPHeaderAuth,
    "token": HTTPTokenAuth,
}


def get_auth(keys):
    """Returns auth provider for requests."""

    def set_auth(request):
        for key in keys:
            auth = key.copy()
            auth.pop("id", None)
            type = auth.pop("type")
            auth = AUTH[type](**auth)
            request = auth(request)
        return request

    return set_auth
