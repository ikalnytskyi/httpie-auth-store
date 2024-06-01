"""Tests shell keychain provider."""

import os
import pathlib
import typing

import pytest

from httpie_auth_store._keychain import ShellKeychain


@pytest.fixture()
def testkeychain() -> ShellKeychain:
    """Keychain instance under test."""

    return ShellKeychain()


def test_secret_retrieved(testkeychain: ShellKeychain, tmp_path: pathlib.Path) -> None:
    """The keychain returns stored secret, no bullshit."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("p@ss", encoding="UTF-8")
    assert testkeychain.get(command=f"cat {secrettxt}") == "p@ss"


def test_secret_retrieved_pipe(testkeychain: ShellKeychain, tmp_path: pathlib.Path) -> None:
    """The keychain returns stored secret even when pipes are used."""

    secrettxt = tmp_path.joinpath("secret.txt")
    secrettxt.write_text("p@ss\nextra", encoding="UTF-8")

    command = rf"cat {secrettxt} | head -n 1 | tr -d {os.linesep!r}"
    assert testkeychain.get(command=command) == "p@ss"


def test_secret_not_found(testkeychain: ShellKeychain, tmp_path: pathlib.Path) -> None:
    """LookupError is raised when no secrets are found in the keychain."""

    secrettxt = tmp_path.joinpath("secret.txt")

    with pytest.raises(LookupError) as excinfo:
        testkeychain.get(command=f"cat {secrettxt}")

    assert str(excinfo.value) == (
        f"No secret found: Command 'cat {secrettxt}' returned non-zero exit status 1."
    )


@pytest.mark.parametrize(("args", "kwargs"), [pytest.param(["echo p@ss"], {}, id="args")])
def test_keywords_only_arguments(
    testkeychain: ShellKeychain,
    args: typing.List[str],
    kwargs: typing.Mapping[str, str],
) -> None:
    with pytest.raises(TypeError):
        testkeychain.get(*args, **kwargs)
