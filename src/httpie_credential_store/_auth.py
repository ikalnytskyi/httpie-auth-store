"""Various authentication providers for python-requests."""

import abc
import collections.abc
import re

import requests.auth

from ._keychain import get_keychain

# These patterns are copied over from built-in `http.client` implementation,
# and are more lenient than RFC definitions for backwards compatibility
# reasons.
is_legal_header_name = re.compile(r"[^:\s][^:\r\n]*").fullmatch
is_illegal_header_value = re.compile(r"\n(?![ \t])|\r(?![ \t\n])").search


def get_secret(value):
    """Retrieve and return secret."""

    if not isinstance(value, collections.abc.Mapping):
        return value

    keychain = get_keychain(value.pop("keychain"))
    return keychain.get(**value)


class AuthProvider(metaclass=abc.ABCMeta):
    """Auth provider interface."""

    @property
    @abc.abstractmethod
    def name(self):
        """Provider/implementation name."""

    @abc.abstractmethod
    def __call__(self, request):
        """Attach authentication to a given request."""


class HTTPBasicAuth(requests.auth.HTTPBasicAuth, AuthProvider):
    """Authentication via HTTP Basic scheme."""

    name = "basic"

    def __init__(self, *, username, password):
        super().__init__(username, get_secret(password))


class HTTPDigestAuth(requests.auth.HTTPDigestAuth, AuthProvider):
    """Authentication via HTTP Digest scheme."""

    name = "digest"

    def __init__(self, *, username, password):
        super().__init__(username, get_secret(password))


class HTTPHeaderAuth(requests.auth.AuthBase, AuthProvider):
    """Authentication via custom HTTP header."""

    name = "header"

    def __init__(self, *, name, value):
        self._name = name
        self._value = get_secret(value)

        if not is_legal_header_name(self._name):
            error_message = (
                f"HTTP header authentication provider received invalid "
                f"header name: {self._name!r}. Please remove illegal "
                f"characters and try again."
            )
            raise ValueError(error_message)

        if is_illegal_header_value(self._value):
            error_message = (
                f"HTTP header authentication provider received invalid "
                f"header value: {self._value!r}. Please remove illegal "
                f"characters and try again."
            )
            raise ValueError(error_message)

    def __call__(self, request):
        request.headers[self._name] = self._value
        return request


class HTTPTokenAuth(requests.auth.AuthBase, AuthProvider):
    """Authentication via token."""

    name = "token"

    def __init__(self, *, token, scheme="Bearer"):
        self._scheme = scheme
        self._token = get_secret(token)

        if is_illegal_header_value(self._scheme):
            error_message = (
                f"HTTP token authentication provider received scheme that "
                f"contains illegal characters: {self._scheme!r}. Please "
                f"remove these characters and try again."
            )
            raise ValueError(error_message)

        if is_illegal_header_value(self._token):
            error_message = (
                f"HTTP token authentication provider received token that "
                f"contains illegal characters: {self._token!r}. Please "
                f"remove these characters and try again."
            )
            raise ValueError(error_message)

    def __call__(self, request):
        request.headers["Authorization"] = f"{self._scheme} {self._token}"
        return request


class HTTPMultipleAuth(requests.auth.AuthBase, AuthProvider):
    """Authentication via multiple providers simultaneously."""

    name = "multiple"

    def __init__(self, *, providers):
        self._providers = [get_auth(provider.pop("provider"), **provider) for provider in providers]

    def __call__(self, request):
        for provider in self._providers:
            request = provider(request)
        return request


_PROVIDERS = {provider_cls.name: provider_cls for provider_cls in AuthProvider.__subclasses__()}


def get_auth(provider, **kwargs):
    return _PROVIDERS[provider](**kwargs)
