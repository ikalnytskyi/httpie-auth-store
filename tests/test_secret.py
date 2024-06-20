import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import typing as t

import keyring
import keyring.backend
import keyring.compat
import pytest

from httpie_auth_store._secret import IdentitySecret, PasswordStoreSecret, ShSecret, SystemSecret


_is_macos = sys.platform == "darwin"


class TestIdentitySecret:
    """Test IdentitySecret."""

    def test_secret_retrieved(self) -> None:
        """The stored secret is retrieved and returned."""

        assert IdentitySecret(secret="p@ss").get() == "p@ss"


class TestShSecret:
    """Test ShSecret."""

    def test_secret_retrieved(self, tmp_path: pathlib.Path) -> None:
        """The stored secret is retrieved and returned."""

        secrettxt = tmp_path.joinpath("secret.txt")
        secrettxt.write_text("p@ss", encoding="UTF-8")
        script = f"cat {secrettxt}"
        assert ShSecret(script=script).get() == "p@ss"

    def test_secret_retrieved_pipe(self, tmp_path: pathlib.Path) -> None:
        """The stored secret is retrieved and returned, even when pipes are used."""

        secrettxt = tmp_path.joinpath("secret.txt")
        secrettxt.write_text("p@ss\nextra", encoding="UTF-8")
        script = rf"cat {secrettxt} | head -n 1 | tr -d {os.linesep!r}"
        assert ShSecret(script=script).get() == "p@ss"

    def test_secret_retrieved_lazy(self, tmp_path: pathlib.Path) -> None:
        """The stored secret is not retrieved until .get() is called."""

        secrettxt = tmp_path.joinpath("secret.txt")
        secret = ShSecret(script=f"cat {secrettxt}")
        secrettxt.write_text("p@ss", encoding="UTF-8")
        assert secret.get() == "p@ss"

    def test_secret_not_found(self, tmp_path: pathlib.Path) -> None:
        """LookupError is raised when no secrets are found."""

        secrettxt = tmp_path.joinpath("secret.txt")
        secret = ShSecret(script=f"cat {secrettxt}")

        with pytest.raises(LookupError) as excinfo:
            secret.get()
        assert str(excinfo.value) == "sh: no secret found"


@pytest.mark.skipif(not shutil.which("pass"), reason="password-store is not found")
class TestPasswordStoreSecret:
    """Test PasswordStoreSecret."""

    if _is_macos:
        # Unfortunately, when 'gpg' is ran on macOS with GNUPGHOME set to a
        # temporary directory and generate-key template pointed to a file in
        # temporary directory too, it complains about using too long names.  It's
        # not clear why 'gpg' complains about too long names, but it's clear that
        # built-in 'tmp_path' fixture produces too long names. That's why on macOS we
        # override 'tmp_path' fixture to return much shorter path to a temporary
        # directory.
        @pytest.fixture()
        def tmp_path(self) -> t.Generator[pathlib.Path, None, None]:
            with tempfile.TemporaryDirectory() as path:
                yield pathlib.Path(path)

    @pytest.fixture(autouse=True)
    def password_store_dir(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
    ) -> pathlib.Path:
        """Set password-store home directory to a temporary one."""

        password_store_dir = tmp_path.joinpath(".password-store")
        monkeypatch.setenv("PASSWORD_STORE_DIR", str(password_store_dir))
        return password_store_dir

    @pytest.fixture()
    def gpg_key_id(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> str:
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

    def test_secret_retrieved(self, gpg_key_id: str) -> None:
        """The stored secret is retrieved and returned."""

        subprocess.check_call(["pass", "init", gpg_key_id])
        subprocess.run(["pass", "insert", "--echo", "service/user"], input=b"p@ss", check=True)
        assert PasswordStoreSecret(pass_name="service/user").get() == "p@ss"

    def test_secret_retrieved_lazy(self, gpg_key_id: str) -> None:
        """The stored secret is not retrieved until .get() is called."""

        secret = PasswordStoreSecret(pass_name="service/user")
        subprocess.check_call(["pass", "init", gpg_key_id])
        subprocess.run(["pass", "insert", "--echo", "service/user"], input=b"p@ss", check=True)
        assert secret.get() == "p@ss"

    def test_secret_not_found(self) -> None:
        """LookupError is raised when no secrets are found."""

        secret = PasswordStoreSecret(pass_name="service/user")
        with pytest.raises(LookupError) as excinfo:
            secret.get()
        assert str(excinfo.value) == "password-store: no secret found: 'service/user'"


class TestSystemSecret:
    """Test SystemSecret."""

    class _InmemoryKeyring(keyring.backend.KeyringBackend):
        """Keyring backend that stores secrets in-memory."""

        @keyring.compat.properties.classproperty
        def priority(self) -> float:
            return 1.0

        def __init__(self) -> None:
            self._keyring = {}

        def get_password(self, service: str, username: str) -> t.Optional[str]:
            return self._keyring.get((service, username))

        def set_password(self, service: str, username: str, password: str) -> None:
            self._keyring[(service, username)] = password

    @pytest.fixture(autouse=True)
    def keyring_backend(self) -> t.Generator[keyring.backend.KeyringBackend, None, None]:
        """Temporary set in-memory keyring as current backend."""

        prev_backend = keyring.get_keyring()
        keyring.set_keyring(self._InmemoryKeyring())
        yield keyring.get_keyring()
        keyring.set_keyring(prev_backend)

    def test_secret_retrieved(self, keyring_backend: keyring.backend.KeyringBackend) -> None:
        """The stored secret is retrieved and returned."""

        keyring_backend.set_password("testsvc", "testuser", "p@ss")
        assert SystemSecret(service="testsvc", username="testuser").get() == "p@ss"

    def test_secret_retrieved_lazy(self, keyring_backend: keyring.backend.KeyringBackend) -> None:
        """The stored secret is not retrieved until .get() is called."""

        secret = SystemSecret(service="testsvc", username="testuser")
        keyring_backend.set_password("testsvc", "testuser", "p@ss")
        assert secret.get() == "p@ss"

    def test_secret_not_found(self) -> None:
        """LookupError is raised when no secrets are found."""

        secret = SystemSecret(service="testsvc", username="testuser")
        with pytest.raises(LookupError) as excinfo:
            secret.get()
        assert str(excinfo.value) == "system: no secret found: 'testsvc'/'testuser'"
