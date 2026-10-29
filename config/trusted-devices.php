<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Trusted devices — "Keep me signed in on this machine?"
|--------------------------------------------------------------------------
|
| After a person gives a two-factor code, they may trust the device for a
| number of days. Until those days end, that device skips the code and, unless
| `auto_sign_in` is off, signs its person in by itself. Log out stops the
| automatic sign-in on that device until the next password sign-in.
|
| Every key below is read through `Olgun\TrustedDevices\Support\Settings`,
| and each one is tested in both positions. A key that nothing reads is a
| defect, not a placeholder.
|
*/

return [

    // Off: no question, no skipped code, no automatic sign-in. Every trust
    // stops working (rows stay until they expire or are forgotten).
    'enabled' => env('TRUSTED_DEVICES_ENABLED', true),

    // The choices the question offers, in days, besides "No, ask every time".
    // A value outside 1..max_days is ignored and `trusted-devices:check`
    // names it. An empty list switches the question off.
    'days' => [1, 7, 30],

    // The longest trust any configuration can give.
    'max_days' => 90,

    // Who may be asked: a Gate ability name (for example 'access admin'), or
    // null for every person with a confirmed two-factor factor. A person who
    // later fails it loses every trust at its next use.
    'ability' => null,

    // The authentication guard the trust signs in with.
    'guard' => 'web',

    // Sign the person in by itself when the session has ended. Off: a trusted
    // device only skips the code; the password is always asked.
    'auto_sign_in' => true,

    // The columns of the user model a trust is made against. Any of them
    // changing (a new password, a new or removed factor) ends every trust.
    'fingerprint' => ['password', 'two_factor_secret', 'two_factor_confirmed_at'],

    // How long the question stays answerable after the code, in seconds. The
    // answer spends it once, atomically, through the cache.
    'offer_seconds' => 120,

    // The most live trusts one person keeps; a new one past it forgets the
    // oldest.
    'max_per_user' => 10,

    'cookie' => [
        'name' => 'trusted_device',
        // The session cookie's path, domain and secure flag are used, so the
        // two reach the same requests. HttpOnly is always on.
        'same_site' => 'lax',
    ],

    'routes' => [
        // Off: register the question and the forget routes yourself.
        'enabled' => true,
        'prefix' => '',
        'middleware' => ['web', 'auth'],
        // Where the answer goes when the session has no intended URL.
        'home' => '/',
    ],

    'views' => [
        // Point at your own Blade view to replace the question page; it gets
        // $choices (list<int>) and $action (the URL to post to).
        'question' => 'trusted-devices::question',
    ],

    'database' => [
        'connection' => null,
        'table' => 'trusted_devices',
    ],

    'migrations' => [
        // Off: publish them (`--tag=trusted-devices-migrations`) and run them
        // yourself. Never publish them while this is on (two migrations would
        // create one table).
        'auto_load' => true,
    ],

    'fortify' => [
        // After Fortify's two-factor challenge, ask the question
        // (Fortify's TwoFactorLoginResponse is bound to ours).
        'ask_after_challenge' => true,
        // Skip Fortify's challenge on a trusted device, by putting our step in
        // place of RedirectIfTwoFactorAuthenticatable in Fortify's login
        // pipeline, when your app has not set its own pipeline.
        'skip_challenge' => true,
    ],

];
