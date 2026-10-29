# CLAUDE.md — olgunozoktas/laravel-trusted-devices

Rules for anybody who edits this package (people and agents). What the package does and how to install it:
[README.md](README.md). The installer's runbook, every knob with its default: `resources/skills/laravel-trusted-devices/SKILL.md`.

## Gates

- `composer test` before every commit: Pint (`--test`), PHPStan at level max, Pest. Never lower the level, add a
  baseline or an ignore to pass; fix the code.
- The suite runs on SQLite in memory; still, never start a second test run beside a running one on the same machine.
- No GitHub Actions (the owner's rule): every gate runs locally.

## Invariants an editor must not break (each has a test; a change that breaks one is a security defect)

1. **A trust is made only with a fresh, one-time offer** (`Support\Offer`): written after an accepted code, it names
   the person, lives `offer_seconds`, and its nonce is spent with `Cache::add()`. Never make a trust from a session
   that proved no code. Tests: `QuestionTest`.
2. **The table never holds a usable secret**: only the SHA-256 of the cookie's secret (compared with `hash_equals`)
   and an HMAC fingerprint. Never log, dispatch or render the secret.
3. **Every use checks again**: not expired (server date), the person's `Eligibility`, and the `Fingerprint`. A trust
   of this person that no longer fits is forgotten for good (`stillTrusts`), so it cannot revive. Tests: `SignInTest`.
4. **A trust stands in for the code, never for the password.** Nothing here may confirm a password.
5. **The host's own choices survive**: the Fortify response is DECORATED (`extend()`), and Fortify's challenge step is
   replaced only while it is still Fortify's own class. Tests: `HostAppTest`.
6. **The middleware runs after the session starts and before `auth`** (the priority list, set in
   `callAfterResolving(HttpKernel)`). Test: `SignInTest`, the last test.
7. **Every config key is read through `Support\Settings`** and tested in both positions (`ConfigContractTest`,
   `tests/BootKnobsOff`, `tests/Customised`). A key nothing reads is a dead knob: remove it or honour it. A value a
   host may vary is a key, never a literal in code.
8. **The list and the events never carry** the hash, the fingerprint, the IP address (the list) or an integer id;
   device names come from `Support\DeviceName`'s fixed lists, never the raw user agent.
9. **User ids are strings** (`user_id` is a string column; compare with `(string)` keys): integer, UUID and ULID keys
   all fit.

## Test harness notes

- `tests/TestCase.php` is an app with Fortify (two-factor, `confirm` on, views on so its named routes exist), a users
  table with Fortify's columns and NO cast on `two_factor_confirmed_at`, an `admin` ability (an email at `admin.test`),
  `/secret` behind `auth` and `/home`.
- Knobs read at boot get their own folder and case (`tests/BootKnobsOff`, `tests/Customised`, mapped in `tests/Pest.php`).
- A JSON test request sends cookies only with `withCredentials()`; `call()` sends none: use the verb helpers.
- Testbench resolves the HTTP kernel at the first request; resolve it first in a test that reads middleware groups.

## Publish tags

`trusted-devices-config`, `trusted-devices-views`, `trusted-devices-migrations` (only with `migrations.auto_load`
off), `trusted-devices-skill` (to `.claude/skills/laravel-trusted-devices`).

## Releases

A CHANGELOG entry, `composer test` green, a commit, then a tag `vX.Y.Z` (semver). A published tag never moves.
