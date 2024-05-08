Credential store plugin for HTTPie
==================================

HTTPie Credential Store is an `HTTPie`_ authentication plugin that looks
for credentials using a given URL and attaches them to the ongoing HTTP
request. That said, you don't need to memorize and/or look for
tokens/username/passwords anymore. Simply add them to the credential
store and everything else will be done for you by this plugin. It goes
without saying that this plugin supports various secured secret storages
such as system keychains or password managers (see keychain providers).

Eager to get started? Just start with installing!

.. code:: bash

   $ python3 -m pip install httpie-credential-store


Usage
-----

.. note:: Please, do not forget to activate the plugin by invoking
          ``http`` with ``-A creds`` option.

Once installed, the plugin will look for credentials in the credential
file. The credential file is stored in HTTPie configuration directory.
So on Linux/macOS, it will look for ``~/.httpie/credentials.json``,
while on Windows - for ``%APPDATA%\httpie\credentials.json``. The
credential file will not be created for you, you're fully responsible
for creating one.

By its nature, the credentials file is a JSON array of credential
records. Each credential record consists of the following properties:

* ``url`` (*required*) is a regular expression pattern that is used to
  map credential record to the ongoing HTTP request. I.e. if the regular
  expression matches URL of the ongoing HTTP request, credentials of
  matched record must be attached.

* ``auth`` (*required*) is an authentication provider to use for a given
  record. The provider will be used to attach credentials to the ongoing
  HTTP request if the record is matched.

* ``id`` (*optional*) is unique identifier of the credential record that
  can be used to solve ambiguousness between two or more matched
  credential records. By using ``id`` one may achieve support of
  multiple accounts for the same service.

Example:

.. code:: json

   [
     {
       "url": "api.github.com",
       "auth": {
         "provider": "token",
         "token": "your-github-oauth-token",
         "scheme": "token"
       }
     },
     {
       "id": "bots",
       "url": "api.github.com",
       "auth": {
         "provider": "token",
         "token": "bots-github-oauth-token",
         "scheme": "token"
       }
     }
   ]

The example above assumes you store your secrets unencrypted in the
credential file. Despite enforcing you to set sole access permissions
for the credential file, it's not secured and, hence, not recommended.
HTTPie Credential Store plugin can pull secrets and other sensitive
information out from password managers or system keychains. For
instance, you can pull your token from the `password store`_ by using
the following credential record:

.. code:: json

   [
     {
       "url": "api.github.com",
       "auth": {
         "provider": "token",
         "scheme": "token",
         "token": {
           "keychain": "password-store",
           "name": "github.com/ikalnytskyi/token"
         }
       }
     }
   ]

Once the credential store is filled, you're ready to use the plugin at
your will. In order to activate the plugin, you must pass ``-A creds``
or ``-A credential-store`` to ``http`` executable.

.. code:: bash

   $ http -A creds https://api.github.com

Optionally, you can provide an ID of the credential record to use by
passing ``-a`` argument.

.. code:: bash

   $ http -A creds -a bots https://api.github.com


Authentication providers
------------------------

HTTPie Credential Store supports both built-in and third-party HTTPie
authentication plugins as well as provides few authentication plugins
on its own.

``basic``
.........

The 'Basic' HTTP authentication scheme as defined in :RFC:`7617`.
Transmits credentials as username/password pairs, encoded using Base64.

.. code:: json

   {
     "provider": "basic",
     "username": "ikalnytskyi",
     "password": "p@ss"
   }

where

* ``username`` is a username to authenticate
* ``password`` is a password of the authenticating user


``digest``
..........

The 'Digest' HTTP authentication scheme as defined in :RFC:`2617`. It
applies a hash function to the username and password before sending them
over the network.

.. code:: json

   {
     "provider": "digest",
     "username": "ikalnytskyi",
     "password": "p@ss"
   }

where

* ``username`` is a username to authenticate
* ``password`` is a password of the authenticating user


``token``
.........

The 'Token' HTTP authentication scheme (also called 'Bearer') transmits
token in the ``Authorization`` HTTP header.

.. code:: json

   {
     "provider": "token",
     "token": "t0k3n",
     "scheme": "JWT"
   }

where

* ``token`` is a token of the authenticating user
* ``scheme`` (optional, default: "Bearer") is an authenticating scheme


``header``
..........

The 'Header' HTTP authentication is not exactly an authentication
scheme. It's rather a way to pass any free-formed HTTP header with
secret or not.

.. code:: json

   {
     "provider": "header",
     "name": "X-Extra-Key",
     "value": "k3y"
   }

where

* ``name`` is an HTTP header name to use
* ``value`` is an HTTP header value to pass


``multiple``
............

This is a fake authentication scheme even in terms of this plugin. It
does no auth but chains and applies one or more providers
simultaneously. It's something you will (likely) never use.

.. code:: json

   {
     "provider": "multiple",
     "providers": [
       {
         "provider": "token",
         "token": "t0k3n"
       },
       {
         "provider": "header",
         "name": "X-Extra-Key",
         "value": "k3y"
       }
     ]
   }

where

* ``providers`` is a list of auth providers to use simultaneously


``hmac``
........

The 'HMAC' authentication is not built-in one and requires the ``httpie-hmac``
plugin to be installed first. Its only purpose here is to serve as an example
of how to invoke third-party authentication plugins from the credentials store.

.. code:: json

   {
     "provider": "hmac",
     "auth": "secret:<HMAC_SECRET>"
   }

where

* ``auth`` is a string with authentication payload passed that is normally
  passed by a user via ``--auth``/``-a`` to HTTPie; each authentication plugin
  may or may not require one


Keychain providers
------------------

The plugin supports a bunch of keychains that can be used to pull
secrets from secured storage.


``shell``
.........

Shell provider is nothing more but a mere shell command to execute. The
command must return a secret to the plugin via standard output stream.
This is a universal approach that can be used to glue together various
unsupported password managers and/or keychains.

Example:

.. code:: json

   {
     "keychain": "shell",
     "command": "cat ~/path/to/secret | tr -d '\n'"
   }

where

* ``command`` is a shell command to execute



``system``
..........

System provider, as the name suggests, use your system keychain to pull
secrets from. It may be **KWallet**, **GNOME Keyring**, **macOS
Keychain** or even **Windows Credential Locker**.

Example:

.. code:: json

   {
     "keychain": "system",
     "service": "github",
     "username": "ikalnytskyi"
   }

where

* ``service`` is a service to pull data for
* ``username`` is a username for that service to pull data for


``password-store``
..................

Password store provider is a bridge between this plugin and the
`password store`_. It invokes ``pass`` on your system and pulls the
secret from the first line of the stored record (normally password).

Example:

.. code:: json

   {
     "keychain": "password-store",
     "name": "github.com/ikalnytskyi"
   }

where

* ``name`` is a pass name in terms of the password store

FAQ
---

* **Q**: How to learn which credentials have been attached to the request?

  **A**: Unfortunately, due to late credentials binding, it's impossible
  to learn which credentials have been used by running ``http --debug``
  command. Nevertheless, one can check amends made by auth providers by
  inspect HTTP headers transmitted within the request by passing ``-v``
  argument to HTTPie: ``http -v``.


.. _HTTPie: https://httpie.org/
.. _password store: https://www.passwordstore.org/
