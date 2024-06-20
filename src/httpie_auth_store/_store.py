import collections.abc
import dataclasses
import json
import pathlib
import stat
import string
import sys
import typing as t
import urllib.parse

import requests

from ._secret import Secret, create_secret


__all__ = ["AuthEntry", "Binding", "AuthStore"]


@dataclasses.dataclass(frozen=True)
class AuthEntry:
    """An entity that defines an authentication type and payload."""

    auth_type: str
    auth: t.Optional[t.Union[str, t.List["AuthEntry"]]] = None

    @classmethod
    def from_mapping(cls, mapping: t.Mapping[str, t.Any]) -> "AuthEntry":
        """Construct an instance from mapping."""

        mapping = dict(mapping)
        if isinstance(mapping.get("auth"), list):
            mapping["auth"] = [cls.from_mapping(entry) for entry in mapping["auth"]]
        return cls(**mapping)


@dataclasses.dataclass(frozen=True)
class Binding(AuthEntry):
    """An entity that binds an authentication entry to HTTP resources."""

    id: t.Optional[str] = None
    resources: t.List[str] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        for resource in self.resources:
            parts = urllib.parse.urlparse(resource)

            if not parts.scheme:
                error_message = f"Broken binding: missing schema in '{resource}'."
                raise ValueError(error_message)

            if not parts.hostname:
                error_message = f"Broken binding: missing hostname in '{resource}'."
                raise ValueError(error_message)

    @classmethod
    def from_mapping(cls, mapping: t.Mapping[str, t.Any]) -> "Binding":
        """Construct an instance from mapping."""

        mapping = dict(mapping)
        if isinstance(mapping.get("auth"), list):
            mapping["auth"] = [AuthEntry.from_mapping(entry) for entry in mapping["auth"]]
        return cls(**mapping)

    def is_request_matched(self, request: requests.PreparedRequest) -> bool:
        """Return 'True' if this binding should be used for the given request."""

        request_parsed = urllib.parse.urlparse(request.url, allow_fragments=False)

        for resource in self.resources:
            resource_parsed = urllib.parse.urlparse(resource, allow_fragments=False)

            if (
                request_parsed.scheme.lower() == resource_parsed.scheme.lower()
                and request_parsed.netloc.lower() == resource_parsed.netloc.lower()
                and request_parsed.path.startswith(resource_parsed.path)
            ):
                return True
        return False


class Secrets(collections.abc.Mapping):
    """The secrets container that retrieves them from providers on-demand."""

    def __init__(self, secrets: t.Dict[str, Secret]) -> None:
        self._secrets = secrets

    def __getitem__(self, key: str):
        return self._secrets[key].get()

    def __len__(self) -> int:
        return len(self._secrets)

    def __iter__(self) -> t.Iterator[str]:
        return self._secrets.__iter__()

    def __contains__(self, key: object) -> bool:
        return self._secrets.__contains__(key)


class AuthStore:
    """Authentication store."""

    DEFAULT_AUTH_STORE: t.Mapping[str, t.Any] = {
        "bindings": [
            {
                "auth_type": "basic",
                "auth": "$PIE_USERNAME:$PIE_PASSWORD",
                "resources": ["https://pie.dev/basic-auth/batman/I@mTheN1ght"],
            },
            {
                "auth_type": "bearer",
                "auth": "$PIE_TOKEN",
                "resources": ["https://pie.dev/bearer"],
            },
        ],
        "secrets": {
            "PIE_USERNAME": "batman",
            "PIE_PASSWORD": "I@mTheN1ght",
            "PIE_TOKEN": "000000000000000000000000deadc0de",
        },
    }

    def __init__(self, bindings: t.List[Binding], secrets: Secrets):
        self._bindings = bindings
        self._secrets = secrets

    @classmethod
    def from_filename(cls, filename: pathlib.Path) -> "AuthStore":
        """Construct an instance from given JSON file."""

        if not filename.exists():
            filename.write_text(json.dumps(cls.DEFAULT_AUTH_STORE, indent=2))
            filename.chmod(0o600)

        # Since an authentication store may contain unencrypted secrets, I
        # decided to follow the same practice SSH does and do not work if the
        # file can be read by anyone but current user. Windows is ignored
        # because I haven't figured out yet how to deal with permissions there.
        if sys.platform != "win32":
            mode = stat.S_IMODE(filename.stat().st_mode)

            if mode & 0o077 > 0o000:
                error_message = (
                    f"Permissions {mode:04o} for '{filename}' are too open. "
                    f"Authentication store MUST NOT be accessible by others."
                )
                raise PermissionError(error_message)

            if mode & 0o400 != 0o400:
                error_message = (
                    f"Permissions {mode:04o} for '{filename}' are too close. "
                    f"Authentication store MUST be readabe by you."
                )
                raise PermissionError(error_message)

        return cls.from_mapping(json.loads(filename.read_text(encoding="UTF-8")))

    @classmethod
    def from_mapping(cls, mapping: t.Mapping[str, t.Any]) -> "AuthStore":
        """Construct an instance from given mapping."""

        bindings = [Binding.from_mapping(binding) for binding in mapping["bindings"]]
        secrets = Secrets({k: create_secret(v) for k, v in mapping.get("secrets", {}).items()})
        return cls(bindings, secrets)

    def get_entry_for(
        self,
        request: requests.PreparedRequest,
        binding_id: t.Optional[str] = None,
    ) -> AuthEntry:
        """Find and return an authentication entry for the given request."""

        for binding in self._bindings:
            if not binding.is_request_matched(request):
                continue

            if binding_id and binding.id != binding_id:
                continue

            return inject_secrets_if_any(binding, self._secrets)

        error_message = f"No binding found for '{request.url}'."
        raise LookupError(error_message)


def inject_secrets_if_any(auth_entry: AuthEntry, secrets: Secrets) -> AuthEntry:
    """Return a new instance of AuthEntry with secrets injected."""

    if isinstance(auth_entry.auth, list):
        return AuthEntry(
            auth_type=auth_entry.auth_type,
            auth=[inject_secrets_if_any(entry, secrets) for entry in auth_entry.auth],
        )

    try:
        auth = auth_entry.auth and string.Template(auth_entry.auth).substitute(secrets)
        return AuthEntry(auth_type=auth_entry.auth_type, auth=auth)
    except KeyError as exc:
        secret_id = str(exc).strip("'")
        error_message = f"Broken authentication entry: missing secret: {secret_id}."
        raise ValueError(error_message) from exc
