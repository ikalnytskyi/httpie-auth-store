"""Tests password-store keychain provider."""

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import typing

import pytest

from httpie_auth_store._keychain import PasswordStoreKeychain


_is_macos = sys.platform == "darwin"


pytestmark = pytest.mark.skipif(
    not shutil.which("pass"),
    reason="password-store is not found",
)


if _is_macos:
    # Unfortunately, when 'gpg' is ran on macOS with GNUPGHOME set to a
    # temporary directory and generate-key template pointed to a file in
    # temporary directory too, it complains about using too long names.  It's
    # not clear why 'gpg' complains about too long names, but it's clear that
    # built-in 'tmp_path' fixture produces too long names. That's why on macOS we
    # override 'tmp_path' fixture to return much shorter path to a temporary
    # directory.
    @pytest.fixture()
    def tmp_path() -> typing.Generator[pathlib.Path, None, None]:
        with tempfile.TemporaryDirectory() as path:
            yield pathlib.Path(path)


@pytest.fixture()
def gpg_key_id(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> str:
    """Return a Key ID of just generated GPG key."""

    gpghome = tmp_path.joinpath(".gnupg")
    gpgtemplate = tmp_path.joinpath("gpg-template")

    monkeypatch.setenv("GNUPGHOME", str(gpghome))
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

    subprocess.check_call(["gpg", "--batch", "--generate-key", gpgtemplate])
    keys = subprocess.check_output(["gpg", "--list-secret-keys"], text=True)

    key = re.search(r"\s+([0-9A-F]{40})\s+", keys)
    if not key:
        error_message = "cannot generate a GPG key"
        raise RuntimeError(error_message)
    return key.group(1)


@pytest.fixture(autouse=True)
def password_store_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> pathlib.Path:
    """Set password-store home directory to a temporary one."""

    passstore = tmp_path.joinpath(".password-store")
    monkeypatch.setenv("PASSWORD_STORE_DIR", str(passstore))
    return passstore


@pytest.fixture()
def testkeychain() -> PasswordStoreKeychain:
    """Keychain instance under test."""

    return PasswordStoreKeychain()


def test_secret_retrieved(testkeychain: PasswordStoreKeychain, gpg_key_id: str) -> None:
    """The keychain returns stored secret, no bullshit."""

    subprocess.check_call(["pass", "init", gpg_key_id])
    subprocess.run(["pass", "insert", "--echo", "service/user"], input=b"f00b@r", check=True)

    assert testkeychain.get(name="service/user") == "f00b@r"


def test_secret_not_found(testkeychain: PasswordStoreKeychain) -> None:
    """LookupError is raised when no secrets are found in the keychain."""

    with pytest.raises(LookupError) as excinfo:
        testkeychain.get(name="service/user")

    assert str(excinfo.value) == "password-store: no secret found: 'service/user'"
