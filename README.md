# pubtkt-php7
PHP 7+ tools for mod_auth_pubtkt

Ideas that will or may land soon:
[x] Drop-in replacement for mcrypt routines based on OpenSSL
[] Function shims to support legacy PHP apps
[] Built-in automated authorization function, so you can support auth_pubtkt on servers without access to the apache configuration.
[x] Support for ECC keys
[] Turnkey login portal with easy built-in user management
[] Support of different authentication backends
[] Basic 2FA mechanisms (TOTP/HOTP)
[] User Certificate-based authentication
[] Webauthn/FIDO? (low priority, I need to read the detailed spec and create a PoC to understand how the process works)
[] OpenID/Oauth? (way later)

## Notes regarding the support of DSA keys (and DSS1 signature scheme)

The code supports DSA/DSS1 if you've got an old enough setup of OpenSSL (1.0.x?) on your machine.
With regard to current cryptographic standards, you should consider switching to either RSA or ECC schemes.
