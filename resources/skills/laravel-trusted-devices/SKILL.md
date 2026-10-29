---
name: laravel-trusted-devices
description: Install, configure and wire olgunozoktas/laravel-trusted-devices ("Keep me signed in on this machine?" after a two-factor code) in a Laravel app, with or without Fortify. Use when adding trusted devices, changing their configuration, building the settings list, or securing an admin step-up on a trusted device.
---

# laravel-trusted-devices — the installer's runbook

The package's README is the reference; this file is the order of work and the whole adjustable surface.

## Install, in order

1. `composer require olgunozoktas/laravel-trusted-devices`
2. `php artisan migrate` (the migration is auto-loaded; never publish it while `migrations.auto_load` is on).
3. `php artisan trusted-devices:check` — exit 0 means ready. It names each problem with its fix.
4. Decide WHO is asked: `trusted-devices.ability` (a Gate ability) or `null` (every person with a confirmed factor).
5. With Fortify: nothing more. With your own sign-in: call `trustsFor()` / `recognise()` after the password, and
   `offerAfterCode()` after your code check (README, "With your own sign-in").
6. Admin step-up: a trust passes it only with a fresh password confirmation, on every admin route; rate limit the
   password confirmation route (README, "Admin panels").
7. Listen to `TrustedDeviceCreated` and send a "Was this you?" mail; write audit lines from all three events.
8. Settings page: `TrustedDeviceList::for()`, the forget route, `forgetOthers()` in "End all other sessions",
   `stopOthersSigningIn()` in "End this session".
9. Where a role is taken away: `forgetAll($user)`, or schedule `trusted-devices:settle` hourly.

## Every knob (config/trusted-devices.php)

Recommend props/config first (tier 1); replace the page only when config cannot express the ask; publish views only on
an explicit human decision.

| Key | Default | Notes |
|---|---|---|
| `enabled` | `true` | env `TRUSTED_DEVICES_ENABLED`. Off stops every trust at once. |
| `days` | `[1, 7, 30]` | Whole days, 1..`max_days`. Empty: no question. |
| `max_days` | `90` | Ceiling 365. |
| `ability` | `null` | Gate ability for being asked AND for every use. |
| `guard` | `'web'` | Guard of the automatic sign-in. |
| `auto_sign_in` | `false` | On: signs in by itself (remember-me strength); refusals must be in `ability`/`Eligibility`. |
| `auto_sign_in_with_authenticate_using` | `false` | The automatic sign-in is refused while `Fortify::authenticateUsing()` is set, unless on. |
| `fingerprint` | `['password', 'two_factor_secret', 'two_factor_confirmed_at']` | A change of any ends every trust; strings, numbers, dates, enums, arrays. |
| `offer_seconds` | `120` | Life of the question after the code. |
| `max_per_user` | `10` | Live trusts per person. |
| `cookie.name` | `'trusted_device'` | Never on `EncryptCookies`' exception list. |
| `cookie.same_site` | `'lax'` | `lax` or `strict`. |
| `routes.enabled` | `true` | Off: register `trusted-devices.create`, `.store`, `.destroy` yourself. |
| `routes.prefix` | `''` | |
| `routes.middleware` | `['web', 'auth']` | Keep `auth`. |
| `routes.home` | `'/'` | Fallback after the answer. |
| `views.question` | `'trusted-devices::question'` | Gets `$choices`, `$action`, `$autoSignIn`; posts `days` (a choice or `never`). |
| `database.connection` | `null` | |
| `database.table` | `'trusted_devices'` | |
| `migrations.auto_load` | `true` | |
| `fortify.ask_after_challenge` | `true` | |
| `fortify.skip_challenge` | `true` | |

Session flash after an answer or a forget: `trusted-devices.status` = `trusted`, `too-late`, `forgotten`,
`already-forgotten`.

## Never

- Never switch `auto_sign_in` on before every sign-in refusal of the app is in `ability` or an `Eligibility` subclass.

- Never let a trusted device skip a PASSWORD confirmation.
- Never put the cookie on `EncryptCookies`' exception list.
- Never publish the migration while `migrations.auto_load` is on.
- Never show the raw user agent, the hash or the fingerprint in a page.
