"""Keychain providers to read secrets from."""

import abc
import subprocess

import keyring


class KeychainProvider(metaclass=abc.ABCMeta):
    """Keychain provider interface."""

    @property
    @abc.abstractmethod
    def name(self):
        """Provider/implementation name."""

    @abc.abstractmethod
    def get(self, **kwargs):
        """Return value from keychain."""


class ShellKeychain(KeychainProvider):
    """Executes arbitrary shell command to retrieve a secret."""

    name = "shell"

    def get(self, *, command):
        try:
            return subprocess.check_output(command, shell=True).decode("UTF-8")
        except subprocess.CalledProcessError as exc:
            error_message = f"No secret found: {exc}"
            raise LookupError(error_message) from exc


class PasswordStoreKeychain(ShellKeychain):
    """Retrieve secret from password-store."""

    name = "password-store"

    def get(self, *, name):
        try:
            # password-store may store securely extra information along with a
            # password. Nevertheless, a password is always a first line.
            text = super().get(command=f"pass {name}")
            return text.splitlines()[0]
        except LookupError as exc:
            error_message = f"password-store: no secret found: '{name}'"
            raise LookupError(error_message) from exc


class SystemKeychain(KeychainProvider):
    """Retrieve secret from the system's keychain."""

    name = "system"

    def __init__(self):
        self._keyring = keyring.get_keyring()

    def get(self, *, service, username):
        secret = self._keyring.get_password(service, username)
        if not secret:
            error_message = (
                f"No secret found for '{service}' service and '{username}' "
                f"username in '{self.name}' keychain."
            )
            raise LookupError(error_message)
        return secret


_PROVIDERS = {provider_cls.name: provider_cls for provider_cls in KeychainProvider.__subclasses__()}


def get_keychain(provider):
    return _PROVIDERS[provider]()
