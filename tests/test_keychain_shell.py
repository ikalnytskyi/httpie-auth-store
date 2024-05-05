"""Tests shell keychain provider."""

import os

import pytest


@pytest.fixture(scope="function")
def testkeychain():
    """Keychain instance under test."""

    # For the same reasons as in tests/test_plugin.py, all imports that trigger
    # HTTPie importing must be postponed till one of our fixtures is evaluated
    # and patched a path to HTTPie configuration.
    from httpie_credential_store import _keychain

    return _keychain.ShellKeychain()


def test_secret_retrieved(testkeychain, tmpdir):
    """The keychain returns stored secret, no bullshit."""

    secrettxt = tmpdir.join("secret.txt")
    secrettxt.write_text("p@ss", encoding="UTF-8")
    assert testkeychain.get(command=f"cat {secrettxt.strpath}") == "p@ss"


def test_secret_retrieved_pipe(testkeychain, tmpdir):
    """The keychain returns stored secret even when pipes are used."""

    secrettxt = tmpdir.join("secret.txt")
    secrettxt.write_text("p@ss\nextra", encoding="UTF-8")

    command = rf"cat {secrettxt.strpath} | head -n 1 | tr -d {os.linesep!r}"
    assert testkeychain.get(command=command) == "p@ss"


def test_secret_not_found(testkeychain, tmpdir):
    """LookupError is raised when no secrets are found in the keychain."""

    secrettxt = tmpdir.join("secret.txt")

    with pytest.raises(LookupError) as excinfo:
        testkeychain.get(command=f"cat {secrettxt.strpath}")

    assert str(excinfo.value) == (
        f"No secret found: Command 'cat {secrettxt.strpath}' returned " f"non-zero exit status 1."
    )


@pytest.mark.parametrize(["args", "kwargs"], [pytest.param(["echo p@ss"], {}, id="args")])
def test_keywords_only_arguments(testkeychain, args, kwargs):
    with pytest.raises(TypeError):
        testkeychain.get(*args, **kwargs)
