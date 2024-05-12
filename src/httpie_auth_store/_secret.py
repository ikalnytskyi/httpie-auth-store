import abc
import subprocess
import typing as t

import keyring


__all__ = [
    "Secret",
    "IdentitySecret",
    "ShSecret",
    "PasswordStoreSecret",
    "SystemSecret",
    "create_secret",
]


class Secret(metaclass=abc.ABCMeta):
    """The secret interface"""

    @abc.abstractmethod
    def get(self) -> str:
        """Retrieve secret from the provider."""


class IdentitySecret(Secret):
    """Secret from in-memory value."""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def get(self) -> str:
        return self._secret


class ShSecret(Secret):
    """Secret from shell script output."""

    def __init__(self, script: str) -> None:
        self._script = script

    def get(self) -> str:
        try:
            return subprocess.check_output(self._script, shell=True, text=True)
        except subprocess.CalledProcessError as exc:
            error_message = "sh: no secret found"
            raise LookupError(error_message) from exc


class PasswordStoreSecret(Secret):
    """Secret from password store."""

    def __init__(self, pass_name: str) -> None:
        self._pass_name = pass_name

    def get(self) -> str:
        try:
            # password-store may store securely extra information along with a
            # password. Nevertheless, a password is always at first line.
            text = subprocess.check_output(["pass", self._pass_name], text=True)
            return text.splitlines()[0]
        except subprocess.CalledProcessError as exc:
            error_message = f"password-store: no secret found: {self._pass_name!r}"
            raise LookupError(error_message) from exc


class SystemSecret(Secret):
    """Secret from operatin system's keychain."""

    def __init__(self, service: str, username: str) -> None:
        self._service = service
        self._username = username
        self._keyring = keyring.get_keyring()

    def get(self) -> str:
        secret = self._keyring.get_password(self._service, self._username)
        if not secret:
            error_message = f"system: no secret found: {self._service!r}/{self._username!r}"
            raise LookupError(error_message)
        return secret


_SECRET_CLASS_MAPPING = {
    "sh": ShSecret,
    "password-store": PasswordStoreSecret,
    "system": SystemSecret,
}


def create_secret(entry: t.Union[str, t.Mapping[str, str]]) -> Secret:
    if isinstance(entry, str):
        return IdentitySecret(entry)

    entry = dict(entry)
    secret_provider = entry.pop("provider", None)

    if secret_provider not in _SECRET_CLASS_MAPPING:
        error_message = "unsupported provider"
        raise KeyError(error_message)

    return _SECRET_CLASS_MAPPING[secret_provider](**entry)
