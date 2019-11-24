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
            raise LookupError(f"No secret found: {exc}")


class SystemKeychain(KeychainProvider):
    """Retrieve secret from the system's keychain."""

    name = "system"

    def __init__(self):
        self._keyring = keyring.get_keyring()

    def get(self, *, service, username):
        secret = self._keyring.get_password(service, username)
        if not secret:
            raise LookupError(
                f"No secret found for '{service}' service and '{username}' "
                f"username in '{self.name}' keychain."
            )
        return secret


_PROVIDERS = {
    provider_cls.name: provider_cls
    for provider_cls in KeychainProvider.__subclasses__()
}


def get_keychain(provider):
    return _PROVIDERS[provider]()
