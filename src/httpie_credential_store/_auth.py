"""Various authentication providers for python-requests."""

import requests.auth


class HTTPHeaderAuth(requests.auth.AuthBase):
    """Authentication via custom HTTP header."""

    def __init__(self, name, value):
        self._header_name = name
        self._header_value = value

    def __call__(self, request):
        request.headers[self._header_name] = self._header_value
        return request


class HTTPTokenAuth(HTTPHeaderAuth):
    """Authentication via token."""

    def __init__(self, token, scheme="Bearer"):
        super(HTTPTokenAuth, self).__init__(
            "Authorization", f"{scheme} {token}"
        )


AUTH = {
    "basic": requests.auth.HTTPBasicAuth,
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
