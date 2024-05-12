import pytest

from httpie_credential_store._store import convert_deprecated_nodes


def test_convert_deprecated_nodes_empty() -> None:
    assert convert_deprecated_nodes([]) == {"bindings": [], "secrets": {}}


@pytest.mark.parametrize("auth_type", ["basic", "digest"])
def test_convert_deprecated_nodes_basic_digest(auth_type: str) -> None:
    nodes = [
        {
            "url": "http://example.com",
            "auth": {
                "provider": auth_type,
                "username": "user",
                "password": "p@ss",
            },
        }
    ]
    assert convert_deprecated_nodes(nodes) == {
        "bindings": [
            {
                "url": "http://example.com",
                "auth_type": auth_type,
                "auth": "user:p@ss",
            }
        ],
        "secrets": {},
    }


@pytest.mark.parametrize("auth_type", ["basic", "digest"])
def test_convert_deprecated_nodes_basic_digest_keychain(auth_type: str) -> None:
    nodes = [
        {
            "url": "http://example.com",
            "auth": {
                "provider": auth_type,
                "username": "user",
                "password": {"keychain": "shell", "command": "cat /secret"},
            },
        }
    ]
    assert convert_deprecated_nodes(nodes) == {
        "bindings": [
            {
                "url": "http://example.com",
                "auth_type": auth_type,
                "auth": "user:$__SECRET_1__",
            }
        ],
        "secrets": {
            "__SECRET_1__": {"keychain": "shell", "command": "cat /secret"},
        },
    }
