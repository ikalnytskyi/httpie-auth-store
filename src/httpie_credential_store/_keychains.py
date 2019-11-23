"""Keychain providers to read secrets from."""

import abc
import subprocess


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

    def get(self, command):
        return subprocess.check_output(command, shell=True).decode("UTF-8")


_PROVIDERS = {
    provider_cls.name: provider_cls
    for provider_cls in KeychainProvider.__subclasses__()
}


def get_keychain(provider):
    return _PROVIDERS[provider]()
