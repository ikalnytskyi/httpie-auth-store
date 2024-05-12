"""Various authentication providers for python-requests."""

import collections.abc
import re
import string
import typing as t

import httpie.cli.argtypes
import httpie.plugins
import httpie.plugins.registry
import requests
import requests.auth


__all__ = ["get_auth"]

# These patterns are copied over from built-in `http.client` implementation,
# and are more lenient than RFC definitions for backwards compatibility
# reasons.
is_legal_header_name = re.compile(r"[^:\s][^:\r\n]*").fullmatch
is_illegal_header_value = re.compile(r"\n(?![ \t])|\r(?![ \t\n])").search


class HeaderAuthPlugin(httpie.plugins.AuthPlugin):
    """Sign requests using a custom HTTP header."""

    name = "HTTPie Custom Header Auth"
    description = "Sign requests using a custom HTTP header"

    auth_type = "header"
    auth_require = True
    auth_parse = False

    class HeaderAuth(requests.auth.AuthBase):
        """Authentication plugin for requests.."""

        def __init__(self, *, name: str, value: str):
            self._name = name
            self._value = value

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

        def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
            request.headers[self._name] = self._value
            return request

    def get_auth(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> requests.auth.AuthBase:
        _ = username
        _ = password
        parsed = httpie.cli.argtypes.parse_auth(self.raw_auth)
        return self.HeaderAuth(name=parsed.key, value=parsed.value)


class CompositeAuth(requests.auth.AuthBase):
    """Authentication via multiple providers simultaneously."""

    def __init__(self, instances: t.List[requests.auth.AuthBase]) -> None:
        self._instances = instances

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        for auth in self._instances:
            request = auth(request)
        return request


def get_auth(binding, secrets) -> requests.auth.AuthBase:
    if not binding.get("auth_type") and isinstance(binding["auth"], list):
        return CompositeAuth([get_auth(auth_entry, secrets) for auth_entry in binding["auth"]])

    try:
        plugin_cls = httpie.plugins.registry.plugin_manager.get_auth_plugin(binding["auth_type"])
    except KeyError:
        pass
    else:
        plugin = plugin_cls()

        auth = string.Template(binding["auth"]).substitute(secrets)
        plugin.raw_auth = auth

        if plugin.auth_parse:
            parsed = httpie.cli.argtypes.parse_auth(auth)
            credentials = {"username": parsed.key, "password": parsed.value}
        else:
            credentials = {"username": None, "password": None}

        return plugin.get_auth(**credentials)
