"""Tests system keychain provider."""

import typing

import keyring
import keyring.backend
import keyring.compat
import pytest

from httpie_credential_store._keychain import SystemKeychain


class _InmemoryKeyring(keyring.backend.KeyringBackend):
    """Keyring backend that stores secrets in-memory."""

    @keyring.compat.properties.classproperty
    def priority(self) -> float:
        return 1.0

    def __init__(self) -> None:
        self._keyring = {}

    def get_password(self, service: str, username: str) -> typing.Optional[str]:
        return self._keyring.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._keyring[(service, username)] = password


@pytest.fixture(autouse=True)
def keyring_backend() -> typing.Generator[keyring.backend.KeyringBackend, None, None]:
    """Temporary set in-memory keyring as current backend."""

    prev_backend = keyring.get_keyring()
    keyring.set_keyring(_InmemoryKeyring())
    yield keyring.get_keyring()
    keyring.set_keyring(prev_backend)


@pytest.fixture()
def testkeychain() -> SystemKeychain:
    """Keychain instance under test."""

    return SystemKeychain()


def test_secret_retrieved(
    testkeychain: SystemKeychain,
    keyring_backend: keyring.backend.KeyringBackend,
) -> None:
    """The keychain returns stored secret, no bullshit."""

    keyring_backend.set_password("testsvc", "testuser", "p@ss")
    assert testkeychain.get(service="testsvc", username="testuser") == "p@ss"


def test_secret_not_found(testkeychain: SystemKeychain) -> None:
    """LookupError is raised when no secrets are found in the keychain."""

    with pytest.raises(LookupError) as excinfo:
        assert testkeychain.get(service="testsvc", username="testuser")

    assert str(excinfo.value) == (
        "No secret found for 'testsvc' service and 'testuser' username in 'system' keychain."
    )


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        pytest.param(["testsvc", "testuser"], {}, id="args"),
        pytest.param(["testsvc"], {"username": "testuser"}, id="args-kwargs"),
    ],
)
def test_keywords_only_arguments(
    testkeychain: SystemKeychain,
    keyring_backend: keyring.backend.KeyringBackend,
    args: typing.List[str],
    kwargs: typing.Mapping[str, str],
) -> None:
    keyring_backend.set_password("testsvc", "testuser", "p@ss")

    with pytest.raises(TypeError):
        testkeychain.get(*args, **kwargs)
