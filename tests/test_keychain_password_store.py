"""Tests password-store keychain provider."""

import os
import re
import subprocess
import sys
import tempfile
import textwrap

import py
import pytest

_is_windows = sys.platform == "win32"
_is_macos = sys.platform == "darwin"


# On Windows, password-store is only supported through Cygwin. There's no much
# sense even to try make these tests green on Windows because I doubt there
# will ever be password-store users on that operating system.
pytestmark = pytest.mark.skipif(
    _is_windows,
    reason="password-store is not supported on windows",
)


if _is_macos:
    # Unfortunately, when 'gpg' is ran on macOS with GNUPGHOME set to a
    # temporary directory and generate-key template pointed to a file in
    # temporary directory too, it complains about using too long names.  It's
    # not clear why 'gpg' complains about too long names, but it's clear that
    # built-in 'tmpdir' fixture produces too long names. That's why on macOS we
    # override 'tmpdir' fixture to return much shorter path to a temporary
    # directory.
    @pytest.fixture()
    def tmpdir():
        with tempfile.TemporaryDirectory() as path:
            yield py.path.local(path)


@pytest.fixture()
def gpg_key_id(monkeypatch, tmpdir):
    """Return a Key ID of just generated GPG key."""

    gpghome = tmpdir.join(".gnupg")
    gpgtemplate = tmpdir.join("gpg-template")

    monkeypatch.setitem(os.environ, "GNUPGHOME", gpghome.strpath)
    gpgtemplate.write_text(
        textwrap.dedent(
            """
                %no-protection
                Key-Type: RSA
                Subkey-Type: RSA
                Name-Real: Test
                Name-Email: test@test
                Expire-Date: 0
                %commit
            """
        ),
        encoding="UTF-8",
    )

    subprocess.check_output(
        f"gpg --batch --generate-key {gpgtemplate}",
        shell=True,
        stderr=subprocess.STDOUT,
    )
    keys = subprocess.check_output(
        "gpg --list-secret-keys", shell=True, stderr=subprocess.STDOUT
    ).decode("UTF-8")

    key = re.search(r"\s+([0-9A-F]{40})\s+", keys)
    if not key:
        error_message = "cannot generate a GPG key"
        raise RuntimeError(error_message)
    return key.group(1)


@pytest.fixture(autouse=True)
def password_store_dir(monkeypatch, tmpdir):
    """Set password-store home directory to a temporary one."""

    passstore = tmpdir.join(".password-store")
    monkeypatch.setitem(
        os.environ,
        "PASSWORD_STORE_DIR",
        passstore.strpath,
    )
    return passstore.strpath


@pytest.fixture()
def testkeychain():
    """Keychain instance under test."""

    # For the same reasons as in tests/test_plugin.py, all imports that trigger
    # HTTPie importing must be postponed till one of our fixtures is evaluated
    # and patched a path to HTTPie configuration.
    from httpie_credential_store import _keychain

    return _keychain.PasswordStoreKeychain()


def test_secret_retrieved(testkeychain, gpg_key_id):
    """The keychain returns stored secret, no bullshit."""

    subprocess.run(f"pass init {gpg_key_id}", shell=True, check=False)
    subprocess.run("pass generate testservice/testuser 14", shell=True, check=False)

    secret = testkeychain.get(name="testservice/testuser")
    assert len(secret) == 14


def test_secret_not_found(testkeychain):
    """LookupError is raised when no secrets are found in the keychain."""

    with pytest.raises(LookupError) as excinfo:
        testkeychain.get(name="testservice/testuser")

    assert str(excinfo.value) == "password-store: no secret found: 'testservice/testuser'"
