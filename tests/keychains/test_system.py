"""Tests system keychain provider."""

import keyring
import pytest


class _InmemoryKeyring(keyring.backend.KeyringBackend):
    """Keyring backend that stores secrets in-memory."""

    def __init__(self):
        self._keyring = {}

    def get_password(self, service, username):
        return self._keyring.get((service, username))

    def set_password(self, service, username, password):
        self._keyring[(service, username)] = password


@pytest.fixture(scope="function", autouse=True)
def keyring_backend():
    """Temporary set in-memory keyring as current backend."""

    prev_backend = keyring.get_keyring()
    keyring.set_keyring(_InmemoryKeyring())
    yield keyring.get_keyring()
    keyring.set_keyring(prev_backend)


@pytest.fixture(scope="function")
def testkeychain():
    """Keychain instance under test."""

    # For the same reasons as in tests/test_credential_store.py, all imports
    # that trigger HTTPie importing must be postponed till one of our fixtures
    # is evaluated and patched a path to HTTPie configuration.
    from httpie_credential_store import _keychains

    return _keychains.SystemKeychain()


def test_secret_retrieved(testkeychain, keyring_backend):
    """The keychain returns stored secret, no bullshit."""

    keyring_backend.set_password("testsvc", "testuser", "p@ss")
    assert testkeychain.get(service="testsvc", username="testuser") == "p@ss"


def test_secret_not_found(testkeychain):
    """LookupError is raised when no secrets are found in the keychain."""

    with pytest.raises(LookupError) as excinfo:
        assert testkeychain.get(service="testsvc", username="testuser")

    assert str(excinfo.value) == (
        "No secret found for 'testsvc' service and 'testuser' username "
        "in 'system' keychain."
    )


@pytest.mark.parametrize(
    ["args", "kwargs"],
    [
        pytest.param(["testsvc", "testuser"], {}, id="args"),
        pytest.param(["testsvc"], {"username": "testuser"}, id="args-kwargs"),
    ],
)
def test_keywords_only_arguments(testkeychain, keyring_backend, args, kwargs):
    keyring_backend.set_password("testsvc", "testuser", "p@ss")

    with pytest.raises(TypeError):
        testkeychain.get(*args, **kwargs)
