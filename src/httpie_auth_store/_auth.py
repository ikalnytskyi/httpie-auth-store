import pathlib
import typing as t

import httpie.cli.argtypes
import httpie.config
import httpie.plugins
import httpie.plugins.registry
import requests
import requests.auth

from ._store import AuthEntry, AuthStore


__all__ = ["StoreAuthPlugin"]


class StoreAuth(requests.auth.AuthBase):
    """Authenticate the given request using authentication store."""

    AUTH_STORE_FILENAME = "auth_store.json"

    def __init__(self, binding_id: t.Optional[str] = None) -> None:
        self._binding_id = binding_id

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        auth_store_dir = pathlib.Path(httpie.config.DEFAULT_CONFIG_DIR)
        auth_store = AuthStore.from_filename(auth_store_dir / self.AUTH_STORE_FILENAME)

        # The credentials store plugin provides extended authentication
        # capabilities, and therefore requires registering extra HTTPie
        # authentication plugins for the given request only.
        httpie.plugins.registry.plugin_manager.register(HeaderAuthPlugin)
        httpie.plugins.registry.plugin_manager.register(CompositeAuthPlugin)

        try:
            auth_entry = auth_store.get_entry_for(request, self._binding_id)
            request_auth = get_request_auth(auth_entry)
            request = request_auth(request)
        finally:
            httpie.plugins.registry.plugin_manager.unregister(CompositeAuthPlugin)
            httpie.plugins.registry.plugin_manager.unregister(HeaderAuthPlugin)
        return request


class HeaderAuth(requests.auth.AuthBase):
    """Authenticate the given request using a free-form HTTP header."""

    def __init__(self, name: str, value: t.Optional[str]) -> None:
        self._name = name
        self._value = value or ""

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request.headers[self._name] = self._value
        return request


class CompositeAuth(requests.auth.AuthBase):
    """Authenticate the given request using several authentication types at once."""

    def __init__(self, instances: t.List[requests.auth.AuthBase]) -> None:
        self._instances = instances

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        for auth in self._instances:
            request = auth(request)
        return request


class StoreAuthPlugin(httpie.plugins.AuthPlugin):
    """Authenticate using credential store."""

    name = "Credential Store HTTP Auth"
    description = __doc__

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
        return StoreAuth(self.raw_auth)


class HeaderAuthPlugin(httpie.plugins.AuthPlugin):
    """Authenticate using a free-form HTTP header."""

    name = "Custom Header HTTP Auth"
    description = __doc__

    auth_type = "header"
    auth_require = True
    auth_parse = False
    raw_auth: str

    def get_auth(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> requests.auth.AuthBase:
        _ = username
        _ = password
        parsed = httpie.cli.argtypes.parse_auth(self.raw_auth)
        return HeaderAuth(parsed.key, parsed.value)


class CompositeAuthPlugin(httpie.plugins.AuthPlugin):
    """Authenticate using several authentication mechanisms simultaneously."""

    name = "Composite HTTP Auth"
    description = __doc__

    auth_type = "composite"
    auth_require = True
    auth_parse = False
    raw_auth: t.List[AuthEntry]

    def get_auth(
        self,
        username: t.Optional[str] = None,
        password: t.Optional[str] = None,
    ) -> requests.auth.AuthBase:
        _ = username
        _ = password
        assert self.raw_auth is not None, "raw_auth must be provided"
        return CompositeAuth([get_request_auth(auth_entry) for auth_entry in self.raw_auth])


def get_request_auth(auth_entry: AuthEntry) -> requests.auth.AuthBase:
    """Construct and return an appropriate authenticator instance."""

    plugin = httpie.plugins.registry.plugin_manager.get_auth_plugin(auth_entry.auth_type)()
    plugin.raw_auth = auth_entry.auth

    if plugin.auth_require and plugin.raw_auth is None:
        error_message = f"Broken '{auth_entry.auth_type}' authentication entry: missing 'auth'."
        raise ValueError(error_message)

    kwargs = {}
    if plugin.auth_parse and plugin.raw_auth is not None:
        parsed = httpie.cli.argtypes.parse_auth(plugin.raw_auth)

        # Both basic and digest authentication plugins don't expect password
        # to be None, and thus cast the input value to string, meaning that
        # the effective password becomes "None" string. This behaviour is weird
        # and unexpected. We better pass an empty string in this case.
        if plugin.auth_type in {"basic", "digest"} and parsed.value is None:
            parsed.value = ""
        kwargs = {"username": parsed.key, "password": parsed.value}

    return plugin.get_auth(**kwargs)
