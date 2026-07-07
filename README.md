<p align="center">
  <a href="https://github.com/getmilpa">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-dark.svg">
      <img src="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-light.svg" alt="Milpa" width="300">
    </picture>
  </a>
</p>

# Milpa OAuth Providers

> **Seven zero-dependency OAuth 2.0 / social-login providers** for the Milpa PHP framework — Google, GitHub, GitLab, Facebook, Apple, Twitch, and the Telegram Login Widget. Pure protocol: build the authorization URL, exchange the code, get back a typed, immutable `UserInfo` DTO. No storage, no sessions, no framework coupling — bring your own.

[![CI](https://github.com/getmilpa/oauth-providers/actions/workflows/ci.yml/badge.svg)](https://github.com/getmilpa/oauth-providers/actions/workflows/ci.yml)
[![Packagist](https://img.shields.io/packagist/v/milpa/oauth-providers.svg)](https://packagist.org/packages/milpa/oauth-providers)
[![PHP](https://img.shields.io/badge/php-%E2%89%A5%208.3-777bb4.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-API%20reference-blue.svg)](https://getmilpa.github.io/oauth-providers/)

`milpa/oauth-providers` implements the OAuth 2.0 authorization-code flow (plus Apple's
JWT-`id_token` variant and Telegram's HMAC-signed widget) against seven identity
providers, each behind its own typed contract in `Milpa\OAuth\Contracts`. Every
provider does exactly three things: build an authorization URL, exchange a code for a
token, and normalize the provider's response into an immutable DTO. **No Doctrine, no
HTTP client, no session, no `milpa/core`** — this package is `curl` and `openssl`
against seven third-party APIs, nothing else. Persisting the user, issuing your own
session, and generating/storing the CSRF `state` are entirely your host application's
job.

## Install

```bash
composer require milpa/oauth-providers
```

## Quick example

Build an authorization URL for GitHub with a CSRF-protection `state`, then handle the
callback:

```php
use Milpa\OAuth\Providers\GitHubOAuthService;

$github = new GitHubOAuthService($_ENV['GITHUB_CLIENT_ID'], $_ENV['GITHUB_CLIENT_SECRET']);

// 1. Redirect the user to GitHub. Generate + store $state yourself (session,
//    signed cookie, whatever your app already uses) — see "The state parameter" below.
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;

header('Location: ' . $github->getAuthUrl('https://app.example.com/callback/github', $state));
```

```php
// 2. In the callback route: verify the state YOU stored matches the one GitHub echoed
//    back, then exchange the code. exchangeCode() makes two curl calls (token, then
//    userinfo) and returns an immutable Milpa\OAuth\DTO\GitHubUserInfo — never null,
//    never an array; a failure throws \RuntimeException.
if (!hash_equals($_SESSION['oauth_state'] ?? '', $_GET['state'] ?? '')) {
    throw new \RuntimeException('OAuth state mismatch — possible CSRF');
}

$user = $github->exchangeCode($_GET['code'], 'https://app.example.com/callback/github');

$user->id;         // GitHub's numeric user id, as a string
$user->login;      // GitHub username
$user->email;      // ?string — null if the user hides their email
$user->toArray();  // ['id' => ..., 'login' => ..., 'name' => ..., 'email' => ..., 'avatar_url' => ...]
```

Every OAuth provider (`GoogleOAuthService`, `GitHubOAuthService`, `GitLabOAuthService`,
`FacebookOAuthService`, `AppleOAuthService`, `TwitchOAuthService`) implements the same
two-method shape: `getAuthUrl(string $redirectUri, ?string $state = null): string` and
`exchangeCode(string $code, string $redirectUri): <Provider>UserInfo`. Swapping
providers means swapping the class you construct — the calling code above is identical
for all six.

## The `state` parameter — CSRF protection is on you

Every OAuth provider's `getAuthUrl()` accepts an optional `?string $state`. When given,
it is appended to the authorization URL as-is and the provider echoes it back
**unmodified** — on the callback's query string for Google/GitHub/GitLab/Facebook/Twitch,
in the `form_post` body for Apple (`response_mode=form_post`).

**This package generates, stores, and verifies nothing.** It only transports whatever
string you pass. Without a `state` round-trip, your callback route has no way to tell a
legitimate redirect from an attacker who crafted their own `code` and pointed a victim's
browser at your callback URL (a login CSRF). The standard mitigation, entirely your
responsibility:

1. Generate a random, unguessable value before redirecting — `bin2hex(random_bytes(16))`,
   not `uniqid()` or anything predictable.
2. Store it server-side, scoped to the user's session (PHP session, signed cookie, or a
   short-lived cache entry keyed by a nonce).
3. On the callback, compare the stored value against the one the provider echoed back
   using `hash_equals()` (constant-time — a plain `===` leaks timing information), and
   reject the request if they don't match, **before** calling `exchangeCode()`.

Skipping `state` doesn't break anything — every provider works fine with `null` — but it
removes your only defense against login CSRF. Always pass one in a browser-facing flow.

## Telegram: HMAC verification, not an authorization code

`TelegramAuthService` has a different, single-method contract —
`verify(array $data): TelegramUserInfo` — because the [Telegram Login
Widget](https://core.telegram.org/widgets/login) is not the authorization-code flow the
other six providers use. There is no `getAuthUrl()`, no redirect, no `code` to exchange:
the widget runs entirely in the browser and POSTs a signed JSON payload (`id`,
`first_name`, `auth_date`, `hash`, …) straight to your callback.

`verify()` reconstructs Telegram's own signature and rejects anything that doesn't
match, exactly as [Telegram's docs](https://core.telegram.org/widgets/login#checking-authorization)
specify:

1. Every field **except `hash`** is sorted by key and joined as `"{$key}={$value}"` lines
   with `\n`, producing the `data_check_string`.
2. The secret key is `SHA-256(bot_token)` (raw bytes, not hex).
3. The expected signature is `HMAC-SHA-256(data_check_string, secret_key)`, compared to
   the payload's `hash` with `hash_equals()` — never `===`.
4. `auth_date` must be within the last 24 hours, or `verify()` throws even with a
   correctly-signed payload (stale widget sessions are rejected).

A correctly signed, fresh payload round-trips to a `TelegramUserInfo`; anything else — a
tampered field, a hash signed with the wrong bot token, an expired `auth_date`, or
missing `id`/`auth_date`/`hash` — throws `\RuntimeException` with a message naming which
check failed:

```php
use Milpa\OAuth\Providers\TelegramAuthService;

$telegram = new TelegramAuthService($_ENV['TELEGRAM_BOT_TOKEN']);

// $_GET (or $_POST) as sent by the Telegram Login Widget's onauth callback.
$user = $telegram->verify($_GET);

$user->getFullName();  // "Ada Lovelace" — joins first_name + last_name, trimmed
$user->username;       // ?string — Telegram usernames are optional
$user->toArray();      // ['id' => ..., 'first_name' => ..., 'last_name' => ..., 'username' => ..., 'photo_url' => ...]
```

Because `verify()` is pure HMAC arithmetic with no network call, it is the one provider
method this package's own test suite exercises end-to-end without mocking `curl` —
see `tests/Providers/TelegramAuthServiceTest.php`.

## Providers at a glance

| Provider | Class | Constructor | Notes |
|---|---|---|---|
| Google | `GoogleOAuthService` | `clientId, clientSecret` | Requests `access_type=offline` + `prompt=consent` so a refresh token is issued every time. |
| GitHub | `GitHubOAuthService` | `clientId, clientSecret` | Scopes `read:user user:email`. |
| GitLab | `GitLabOAuthService` | `clientId, clientSecret, instanceUrl = ''` | `instanceUrl` defaults to `https://gitlab.com`; pass your self-hosted base URL (e.g. `https://git.mycompany.com`) to support a private instance. `getInstanceUrl()` reads it back. |
| Facebook | `FacebookOAuthService` | `appId, appSecret` | Uses Graph API v21.0. |
| Apple | `AppleOAuthService` | `clientId, teamId, keyId, privateKey` | Signs its own JWT `client_secret` from your `.p8` private key; user info comes from the `id_token`, not a userinfo endpoint. Apple sends the user's **name only on the first authorization** — persist it then, or it's gone. Uses `response_mode=form_post`, so `code` arrives via POST body, not the query string. |
| Twitch | `TwitchOAuthService` | `clientId, clientSecret` | Scope `user:read:email`; the Helix userinfo call additionally requires a `Client-Id` header alongside the bearer token (handled internally). |
| Telegram | `TelegramAuthService` | `botToken` | Not OAuth 2.0 — see [Telegram: HMAC verification](#telegram-hmac-verification-not-an-authorization-code) above. |

Each `getAuthUrl()`/`exchangeCode()` provider throws `\RuntimeException` immediately if
constructed with empty credentials, before making any network call.

## Requirements

- PHP **≥ 8.3**
- `ext-curl` — every OAuth provider's token/userinfo calls
- `ext-openssl` — `AppleOAuthService` only, to sign its JWT client secret

No Composer dependencies beyond PHP itself: this package does not require `milpa/core`
or any other Milpa package.

## Documentation

**Full API reference: [getmilpa.github.io/oauth-providers](https://getmilpa.github.io/oauth-providers/)** —
generated straight from the source DocBlocks and dressed with the Milpa design system.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report security
issues via [SECURITY.md](SECURITY.md), and note that this project follows a
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE) © TeamX Agency.

---

Milpa is designed, built, and maintained by **[TeamX Agency](https://teamx.agency/?utm_source=github&utm_medium=readme&utm_campaign=milpa&utm_content=oauth-providers)**.
