# Changelog

All notable changes to `olgunozoktas/laravel-trusted-devices`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- "Keep me signed in on this machine?" after a two-factor code: 1, 7 or 30 days (configurable), or "No, ask every
  time".
- A trusted device skips Fortify's two-factor challenge and signs its person in by itself; Log out stops the automatic
  sign-in on that device until the next password sign-in.
- The trust store (`trusted_devices`): the SHA-256 of the cookie's secret and an HMAC fingerprint of the password and
  the second factor; soft deletes; at most `max_per_user` live trusts.
- A one-time offer (120 s, a nonce spent with `Cache::add()`), so a stolen session cannot trust a device for itself.
- `TrustedDeviceList` (list, forget, forget the others, stop the others signing in, forget all) and a scoped forget route.
- Events: `TrustedDeviceCreated`, `TrustedDeviceUsed`, `TrustedDeviceForgotten`.
- Commands: `trusted-devices:check` (reads only; fails on a guard that cannot sign in or is not Fortify's, warns on
  settings that weaken a trust) and `trusted-devices:settle`.
- The automatic sign-in is off by default (`auto_sign_in`), and refused while `Fortify::authenticateUsing()` is set
  unless `auto_sign_in_with_authenticate_using` is on.
- An independent security review before the first release: no way to make or use a trust without a fresh code or for
  another account; its findings on robustness, documentation and tests are fixed (82 tests).
