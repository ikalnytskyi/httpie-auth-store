"""Credentials are managed here."""

import collections.abc
import copy
import json
import os
import re
import stat
import sys
import typing as t

import httpie.config

from ._auth import get_auth
from ._keychain import get_keychain


class Secrets(collections.abc.Mapping):
    """Secrets container."""

    def __init__(self, secrets: t.Dict[str, t.Any]) -> None:
        self._secrets = secrets

    def __getitem__(self, key: str):
        secret = self._secrets[key]

        if not isinstance(secret, collections.abc.Mapping):
            return secret

        secret = copy.copy(secret)
        keychain = get_keychain(secret.pop("keychain"))
        return keychain.get(**secret)

    def __len__(self) -> int:
        return len(self._secrets)

    def __iter__(self) -> t.Iterator[str]:
        return self._secrets.__iter__()

    def __contains__(self, key: object) -> bool:
        return self._secrets.__contains__(key)


class CredentialStore:
    """Credential store, manages your credentials."""

    def __init__(self, store):
        self._bindings = store["bindings"]
        self._secrets = Secrets(store.get("secrets", {}))

    def get_auth_for(self, url, credential_id=None):
        """Return requests' auth instance."""

        for binding in self._bindings:
            if re.search(binding["url"], url):
                if credential_id and binding.get("id") != credential_id:
                    continue

                return get_auth(binding, self._secrets)

        message = f"No credentials found for a given URL: '{url}'"
        if credential_id:
            message += f" (id='{credential_id}')"
        raise LookupError(message)


def get_credential_store(name, directory=None):
    """Returns a credential store that can be used to lookup credentials."""

    credentials = []
    credential_file = os.path.join(directory or httpie.config.DEFAULT_CONFIG_DIR, name)

    if not os.path.exists(credential_file):
        error_message = (
            f"Credentials file '{credential_file}' is not found; "
            f"please create one and try again."
        )
        raise FileNotFoundError(error_message)

    mode = stat.S_IMODE(os.stat(credential_file).st_mode)

    # Since credentials file may contain unencrypted secrets, I decided to
    # follow the same practice SSH does and do not work if the file can be
    # read by anyone but current user. However, I haven't figured how to
    # set correct permissions on Windows (I don't use this platform), let's
    # ignore this platform for a while.
    if sys.platform != "win32":
        if mode & 0o077 > 0o000:
            error_message = (
                f"Permissions '{mode:04o}' for '{credential_file}' are too "
                f"open; please ensure your credentials file is NOT accessible "
                f"by others."
            )
            raise PermissionError(error_message)

        if mode & 0o400 != 0o400:
            error_message = (
                f"Permissions '{mode:04o}' for '{credential_file}' are too "
                f"close; please ensure your credentials file CAN be read by "
                f"you."
            )
            raise PermissionError(error_message)

    with open(credential_file, encoding="UTF-8") as f:
        credentials = json.load(f)

    return CredentialStore(convert_deprecated_nodes(credentials))


secret_id_counter = 0


def convert_deprecated_nodes(
    store: t.Union[t.List[t.MutableMapping[str, t.Any]], t.MutableMapping[str, t.Any]],
) -> t.Mapping[str, t.Any]:
    """Get store v2 from store v1."""

    if isinstance(store, collections.abc.Sequence):
        converted_store = {"bindings": store, "secrets": {}}
    else:
        converted_store = store
        converted_store.setdefault("secrets", {})

    for binding in converted_store["bindings"]:
        if isinstance(binding["auth"], collections.abc.Mapping):
            binding.update(convert_deprecated_auth(binding["auth"], converted_store["secrets"]))

    return converted_store


def convert_deprecated_auth(auth, secrets):
    # TODO: ESCAPE PLAIN SECRETS (i.e. use $)
    global secret_id_counter

    if auth["provider"] in ("basic", "digest"):
        username = auth["username"]
        password = auth["password"]

        if isinstance(password, collections.abc.Mapping):
            secret_id_counter += 1
            secret_id = f"__SECRET_{secret_id_counter}__"
            secrets[secret_id] = password
            password = f"${secret_id}"

        return {"auth_type": auth["provider"], "auth": f"{username}:{password}"}

    elif auth["provider"] == "header":
        name = auth["name"]
        value = auth["value"]

        if isinstance(value, collections.abc.Mapping):
            secret_id_counter += 1
            secret_id = f"__SECRET_{secret_id_counter}__"
            secrets[secret_id] = value
            value = f"${secret_id}"

        return {"auth_type": auth["provider"], "auth": f"{name}:{value}"}

    elif auth["provider"] == "token":
        scheme = auth.get("scheme", "Bearer")
        token = auth["token"]

        if isinstance(token, collections.abc.Mapping):
            secret_id_counter += 1
            secret_id = f"__SECRET_{secret_id_counter}__"
            secrets[secret_id] = token
            token = f"${secret_id}"

        return {"auth_type": "header", "auth": f"Authorization:{scheme} {token}"}

    elif auth["provider"] == "multiple":
        return {
            "auth_type": None,
            "auth": [
                convert_deprecated_auth(auth_entry, secrets) for auth_entry in auth["providers"]
            ],
        }

    error_message = "unsupported node; must never happen"
    raise ValueError(error_message)
