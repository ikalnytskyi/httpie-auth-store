# HTTPie Auth Store

> [!NOTE]
>
> The plugin was renamed from `httpie-credential-store` to `httpie-auth-store`
> primarily due to backward incompatible changes and because the new name
> better reflects its nature.

HTTPie Auth Store is an [HTTPie] authentication plugin that automatically
selects the appropriate authentication type and payload from a file containing
authentication bindings, then uses them for the current request. No more
memorizing or searching for tokens, usernames, or passwords — simply add them
to the authentication store, and the plugin handles the rest. This plugin also
supports various secret storage options, such as system keychains and password
managers (see supported [Secret providers]).

Eager to get started? Just start with installing!

```sh
httpie cli plugins install httpie-auth-store
```

or via `pip` in the same python environment where HTTPie is installed:

```sh
python3 -m pip install httpie-auth-store
```


## Table of Content

* [Usage](#usage)
* [Authentication types](#authentication-types)
  * [basic](#basic)
  * [digest](#digest)
  * [bearer](#bearer)
  * [header](#header)
  * [composite](#composite)
  * [hmac](#hmac)
* [Secret providers](#secret-providers)
  * [sh](#sh)
  * [system](#system)
  * [password-store](#password-store)
* [FAQ](#faq)


## Usage

> [!IMPORTANT]
>
> Do not forget to pass `-A store` or `--auth-type store` to HTTPie in order to
> activate the plugin.

Once installed, the plugin looks for `auth_store.json` located in the HTTPie
configuration directory. On macOS and Linux, it tries the following locations:
`$HTTPIE_CONFIG_DIR/auth_store.json`, `$HOME/.httpie/auth_store.json` and
`$XDG_CONFIG_HOME/httpie/auth_store.json`; on Windows —
`%HTTPIE_CONFIG_DIR%\auth_store.json` and `%APPDATA%\httpie\auth_store.json`

> [!NOTE]
>
> The authentication store is not created automatically; it is the user's
> responsibility to create one.

The authentication store is a JSON file that contains two sections: `bindings`
and `secrets`:

```json
{
  "bindings": [
    {
      "auth_type": "bearer",
      "auth": "$GITHUB_TOKEN",
      "resources": ["https://api.github.com/"]
    },
    {
      "id": "bots",
      "auth_type": "bearer",
      "auth": "ZWFzdGVyIGVnZwo",
      "resources": ["https://api.github.com/"]
    },
  ],
  "secrets": {
    "GITHUB_TOKEN": {
      "provider": "system",
      "service": "github.com",
      "username": "ikalnytskyi"
    }
  }
}
```

Each _binding_ is a JSON object that contains the following keys:

* `id` (*str*, *optional*) is an authentication binding ID that can be used to
  overcome ambiguity when two or more bindings are matched.

* `auth_type` (*str*, *required*) is an authentication type supported by HTTPie,
  either natively or via third-party plugins. See [Authentication types] for
  details.

* `auth` (*str*, *optional*) is an authentication payload for the given
  authentication type. Required for certain authentication types, optional for
  others. Tokens started with `$` are replaced with secrets referred by those
  tokens. The `$` sign must be escaped (`$$`) to remain untouched.

* `resources` (*List\[str\]*, *required*) is an array of URLs to activate this
  binding for. Must contain both scheme and hostname.

Each _secret_ is a KV-pair, where key is a secret name, and value is either a
secret itself or a JSON object that specified how a secret must be retrieved
from secure storage. The JSON object must contain the `provider` key. Presence
of other keys are provider dependent (see [Secret providers] section below).

Once the authenticate store is set up, just pass `-A store` to HTTPie to
activate the plugin and perform some magic for you.

```sh
http -A store https://api.github.com
```

If there are two or more authentication bingind in the store that match the
same resource, you can select appropriate binding by providing a binding ID by
passing `-a` or `--auth` to HTTPie. This might come handy when you have
multiple accounts on the same web resource.

```sh
http -A store -a bots https://api.github.com
```


## Authentication types

HTTPie Auth Store supports both built-in and third-party HTTPie authentication
types as well as provides few authentication types on its own.

> [!TIP]
>
> It's advised to store your secrets in password managers instead of storing
> them directly in the authentication store file.

### basic

The 'Basic' HTTP authentication type as defined in RFC 7617. Transmits
credentials as username/password pairs, encoded using Base64.

```json
{
  "auth_type": "basic",
  "auth": "ihor:p@ss"
}
```

where

* `auth` is a `:`-delimited username/password pair

### digest

The 'Digest' HTTP authentication type as defined in RFC 2617. It applies a hash
function to the username and password before sending them over the network.


```json
{
  "auth_type": "digest",
  "auth": "ihor:p@ss"
}
```

where

* `auth` is a `:`-delimited username/password pair

### bearer

The 'Bearer' HTTP authentication type transmits token in the `Authorization`
HTTP header.

```json
{
  "auth_type": "bearer",
  "auth": "t0ken"
}
```

where

* `auth` is a bearer token to authenticate with

### header

The 'Header' authentication type is not exactly an authentication scheme. It's
rather a way to set a free-formed HTTP header that may or may not contain any
secret material.

```json
{
  "auth_type": "header",
  "auth": "X-Secret:s3cret"
}
```

where

* `auth` is a `:`-delimited HTTP header name/value pair

The 'Header' authentication type can be used to bypass any kind of limitations
imposed by built-in or third-party authentication types. For instance, you can
pass a bearer token with non-default authentication scheme, say `JWT`, without
breaking a sweat.

```json
{
  "auth_type": "header",
  "auth": "Authorization:JWT t0ken"
}
```

### composite

The 'Composite' authentication type is a not an authentication type either.
It's a way to use multiple authentication types simultaneously. It might come
handy when in addition to `basic` or `bearer` authentication, you have to
supply an extra secret via custom HTTP header.

```json
{
  "auth_type": "composite",
  "auth": [
    {
      "auth_type": "bearer",
      "auth": "t0ken"
    },
    {
      "auth_type": "header",
      "auth": "X-Secret:s3cret"
    }
  ]
}
```

where

* `auth` is a list of authentication entries, as supported by HTTPie

### hmac

The 'HMAC' authentication type is not built-in and requires the `httpie-hmac`
plugin to be installed first. Its only purpose here is to serve as an example
of how to use a third-party authentication type in the authentication store.

```json
{
 "auth_type": "hmac",
 "auth": "secret:czNjcjN0Cg=="
}
```

where

* `auth` is a HMAC specific authentication payload


## Secret providers

The plugin supports some secret providers that can be used to retrieve tokens,
passwords and other secret materials from various secured storages.

### sh

The 'Sh' secret provider retrieves a secret from the standard output of the
shell script. This is a universal approach that can be used to retrieve secrets
from unsupported password managers using their command line interfaces.

```json
{
  "provider": "sh",
  "script": "cat ~/path/to/secret | tr -d '\n'"
}
```

where

* `script` is a shell script to execute

### system

The 'System' secret provider, as the name suggests, retrieves a secret from
your system keychain. It may be KWallet, GNOME Keyring, macOS Keychain or even
Windows Credential Locker.

```json
{
  "provider": "system",
  "service": "github",
  "username": "ikalnytskyi"
}
```

where

* `service` is a service to retrieve a secret from
* `username` is a username to retrieve a secret from

### password-store

The 'Password Store' secret provider invokes the `pass` executable on your
system, and retrieves the secret from the first line of referred record.

```json
{
  "provider": "password-store",
  "name": "github.com/ikalnytskyi"
}
```

where

* `name` is a password-store entry name to retrieve a secret from

## FAQ

* **Q**: How to get know what authentication is used for the given request?

  **A**: You can run HTTPie with `--offline` argument to print the request
  header along with injected authentication credentials.


[HTTPie]: https://httpie.org/
[Authentication types]: #authentication-types
[Secret providers]: #secret-providers
[password-store]: https://www.passwordstore.org/
