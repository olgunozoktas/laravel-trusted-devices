# Laravel Trusted Devices

"Keep me signed in on this machine?" for Laravel and [Laravel Fortify](https://laravel.com/docs/fortify).

After a person gives a two-factor code, they may trust the device for a number of days (1, 7 or 30 by default). Until
those days end, that device:

1. does **not** ask for the two-factor code at sign-in, and
2. when you switch `auto_sign_in` on, **signs its person in by itself** when the session has ended.

**Log out** stops the automatic sign-in on that device until the next password sign-in; the code stays skipped until
the trust ends. Each person can see and forget their trusted devices.

The package was built for [DataVisitors](https://datavisitors.com), where an independent security review re-broke
every rule below before the first release.

## Requirements

- PHP 8.4
- Laravel 12 or 13
- Laravel Fortify 1.x for the ready-made integration (optional: the core works with your own sign-in)
- A user model with a confirmed second factor (Fortify's `two_factor_secret` and `two_factor_confirmed_at`)

## Install

```bash
composer require olgunozoktas/laravel-trusted-devices
php artisan migrate
php artisan trusted-devices:check
```

`trusted-devices:check` reads your configuration, routes, middleware, guards and table, changes nothing, and names
each problem with its fix (and, as warnings, the settings that weaken a trust). With Fortify, that is all: the question appears after Fortify's two-factor challenge, and a trusted
device skips the challenge.

Publish the configuration to change it:

```bash
php artisan vendor:publish --tag=trusted-devices-config
```

## How it works

```
password + code ──► "Keep me signed in on this machine?" ──► For 7 days
                                                               │
               a random 64-character secret in an encrypted, HttpOnly cookie;
               only its SHA-256 in the trusted_devices table
                                                               │
next visit ──► session ended? ──► the device signs its person in by itself
next sign-in ──► password only, no code
Log out ──► no automatic sign-in on this device until the next password sign-in
```

A trust works only while it still fits the account. Every use checks again that:

- the trust is not expired (the date is the server's, not the cookie's) or forgotten;
- the person still has a confirmed second factor and still passes `trusted-devices.ability`;
- the password hash and the second factor are the ones the trust was made against (an HMAC fingerprint: a new
  password or a new authenticator ends every trust).

A trust of a person that no longer fits them is forgotten for good, so it cannot come back when, for example, their
role is given back.

## Configuration

Every key is read through one class (`Olgun\TrustedDevices\Support\Settings`), and each one is tested in both
positions.

| Key | Default | What it does |
|---|---|---|
| `enabled` | `true` (`TRUSTED_DEVICES_ENABLED`) | Off: no question, no skipped code, no automatic sign-in. |
| `days` | `[1, 7, 30]` | The choices, besides "No, ask every time". An empty list switches the question off, and no trust works while it is empty. |
| `max_days` | `90` | The longest trust (at most 365). A `days` value above it is not offered, and `check` names it. |
| `ability` | `null` | A Gate ability a person must pass to be asked (for example `'access admin'`). `null`: every person with a confirmed factor. |
| `guard` | `'web'` | The guard the automatic sign-in uses. |
| `auto_sign_in` | `false` | On: a trusted device signs its person in by itself (as strong as a remember-me cookie for its days; read "What a trust bypasses"). Off: it only skips the code. |
| `auto_sign_in_with_authenticate_using` | `false` | While `Fortify::authenticateUsing()` is set, the automatic sign-in is refused; turn this on only when every refusal of that callback is also in `ability` or your `Eligibility`. |
| `fingerprint` | `['password', 'two_factor_secret', 'two_factor_confirmed_at']` | The columns a change of which ends every trust. Strings, numbers, dates, enums and arrays are read; another type is refused. |
| `offer_seconds` | `120` | How long the question stays answerable after the code. |
| `max_per_user` | `10` | The most live trusts one person keeps; a new one past it forgets the oldest. |
| `cookie.name` | `'trusted_device'` | The cookie's name. Keep it off `EncryptCookies`' exception list. |
| `cookie.same_site` | `'lax'` | `'lax'` or `'strict'`. |
| `routes.enabled` | `true` | Off: register the routes yourself. |
| `routes.prefix` | `''` | A prefix for the routes. |
| `routes.middleware` | `['web', 'auth']` | The middleware of the routes. Keep `auth`. |
| `routes.home` | `'/'` | Where the answer goes when the session has no intended URL. |
| `views.question` | `'trusted-devices::question'` | Your own view for the question (it gets `$choices`, `$action` and `$autoSignIn`). A missing view falls back to the package's page. |
| `database.connection` | `null` | The connection of the table. |
| `database.table` | `'trusted_devices'` | The table's name. |
| `migrations.auto_load` | `true` | Off: publish the migration (`--tag=trusted-devices-migrations`) and run it yourself. Never both. |
| `fortify.ask_after_challenge` | `true` | Ask the question after Fortify's two-factor challenge. |
| `fortify.skip_challenge` | `true` | Skip Fortify's challenge on a trusted device. |

## With Fortify

Nothing to do. The package:

- **decorates** whatever your app bound to Fortify's `TwoFactorLoginResponse` (with the container's `extend()`): after
  an accepted code it asks the question; otherwise your own response answers. A JSON request is never redirected.
- puts its own step in place of Fortify's `RedirectIfTwoFactorAuthenticatable` in the login pipeline, **only while**
  that step is still Fortify's own class. On a trusted device it validates the password as Fortify does, once, and
  goes on without the challenge.

An Inertia request gets a `409` with `X-Inertia-Location`, so the question opens as a full page. If your app has its
own two-factor step, keep it, and call the API below from it.

## With your own sign-in

```php
use Olgun\TrustedDevices\TrustedDevices;

// In your login controller, after the password is valid:
if ($trustedDevices->trustsFor($request, $user)) {
    Auth::login($user, $request->boolean('remember'));
    $request->session()->regenerate();
    $trustedDevices->recognise($request, $user); // the device signs in by itself again; fires TrustedDeviceUsed

    return redirect()->intended('/');
}
// ... otherwise ask for the code.

// After your own code check succeeded:
if ($trustedDevices->offerAfterCode($request, $user)) {
    return redirect()->route('trusted-devices.create');
}
```

Log out by any route is handled: the package listens to Laravel's `Logout` and `CurrentDeviceLogout` events.

## What a trust bypasses

Read this before you switch `auto_sign_in` on.

- **Without `auto_sign_in` (the default),** a trusted device skips only the two-factor code. The password is asked at
  every sign-in, so your login code (bans, locked accounts, `Fortify::authenticateUsing()`) still runs.
- **With `auto_sign_in`,** a trusted device signs its person in for up to `max_days` without your login code, as a
  remember-me cookie does. Put every sign-in refusal of your app in `ability` (a Gate ability) or in a subclass of
  `Olgun\TrustedDevices\Support\Eligibility` bound in the container; or call `TrustedDeviceList::forgetAll($user)` when you
  ban a person. While `Fortify::authenticateUsing()` is set, the automatic sign-in is refused unless you set
  `auto_sign_in_with_authenticate_using`.
- **A trust ends by itself** when the password hash changes (also a rehash on login after you raise the bcrypt rounds
  or change the algorithm), when `APP_KEY` changes (the fingerprint is an HMAC with it), and when the second factor is
  set up again. Each then asks for the code once more; this fails closed.
- **Laravel's remember-me cookie is separate.** Forget does not end a remember-me cookie on that device; when you end
  "all other sessions", also rotate the remember token.

## Admin panels and step-up screens: keep the password

A trusted device stands in for the **code**, never for the **password**. If your app asks for a second code before an
admin panel (a step-up), let a trusted device pass it **only with a fresh password confirmation**, on every admin
route — also the ones outside your `password.confirm` group:

```php
if ($trustedDevices->trustsFor($request, $user)) {
    $fresh = time() - (int) $request->session()->get('auth.password_confirmed_at', 0) < config('auth.password_timeout');

    return $fresh ? $next($request) : redirect()->guest(route('password.confirm'));
}
```

On a trusted device the password is then the one gate, so **rate limit your password confirmation**. Fortify's
`POST /user/confirm-password` has no limit of its own; declare it again with a throttle:

```php
Route::post('user/confirm-password', [\Laravel\Fortify\Http\Controllers\ConfirmablePasswordController::class, 'store'])
    ->middleware(['web', 'auth', 'throttle:5,1'])
    ->name('password.confirm.store');
```

## A settings page

```php
use Olgun\TrustedDevices\TrustedDeviceList;

$rows = $trustedDeviceList->for($request, $user);
// list of ['uuid', 'device' => 'Chrome on macOS', 'is_current', 'signs_in', 'until', 'until_at', 'last_used']
```

- **Forget:** a form that sends `DELETE` to `route('trusted-devices.destroy', ['uuid' => $row['uuid']])`. It is scoped
  to the signed-in person and is a soft delete.
- **"End all other sessions":** call `$trustedDeviceList->forgetOthers($request, $user)`, or a trusted device signs in
  again by itself a moment later.
- **"End this session" (one row):** a session row does not say which device made it, so call
  `$trustedDeviceList->stopOthersSigningIn($request, $user)`: the other devices then ask for the password (not the
  code) at their next sign-in.
- **A role taken away:** call `$trustedDeviceList->forgetAll($user)`, or schedule `trusted-devices:settle` (hourly),
  so that an unused device (a lost laptop) cannot come back when the role does.

The list never carries the secret's hash, the fingerprint, the IP address or an integer id; a device's name comes from
a fixed list, never the raw user agent.

## Events

Write your audit log and your "Was this you?" mail from these. None carries the secret, and a queued listener gets
the models by their keys (`SerializesModels`), never their attributes.

| Event | When |
|---|---|
| `TrustedDeviceCreated` (`user`, `device`, `days`, `ipAddress`) | A device was trusted. Send the owner a mail. |
| `TrustedDeviceUsed` (`user`, `device`, `how`, `ipAddress`) | `AUTO_SIGN_IN` or `CODE_SKIPPED`. |
| `TrustedDeviceForgotten` (`user`, `device`, `reason`) | `FORGOTTEN`, `OTHERS`, `NO_LONGER_FITS`, `REPLACED`, `LIMIT`. |

## The question page

Three levels, the first is the one to start with:

1. **Config:** `views.question` points at your own Blade view; it gets `$choices` (a list of days), `$action` (the URL
   to post to) and `$autoSignIn` (say "signs you in by itself" only when it is true). Post `days` = one of the choices, or `never`.
2. **Override the package view** in `resources/views/vendor/trusted-devices/question.blade.php`.
3. **Publish it** (`--tag=trusted-devices-views`) to own it fully.

After the answer the session holds `trusted-devices.status`: `trusted`, `too-late`, `forgotten` or
`already-forgotten`.

## Security notes

- **A trust is made only right after a code.** The question can be answered once, within `offer_seconds`, by the
  person who gave the code: a stolen session cookie cannot trust a device for itself.
- **The database never holds a usable secret.** Only the SHA-256 of the cookie's secret and an HMAC fingerprint.
- **The cookie** is encrypted by your app's `EncryptCookies`, HttpOnly, and SameSite `lax` or `strict`.
- **What it cannot protect:** a trusted device is a key that lives on that device. Until its days end, whoever has
  that browser profile (an unlocked laptop, malware that reads the cookie store) is signed in. Keep the password on
  your admin pages, tell people to choose "No" on a shared computer, and send the `TrustedDeviceCreated` mail.
- **`ability => null`** offers the question to every person with a confirmed factor. Set an ability to offer it to
  administrators only.

## Testing

```bash
composer test   # Pint, PHPStan (level max), Pest
```

## Licence

MIT. See [LICENSE](LICENSE).
