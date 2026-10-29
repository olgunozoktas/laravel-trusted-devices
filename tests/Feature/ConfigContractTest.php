<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\View;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Olgun\TrustedDevices\TrustedDevices;

/**
 * Every knob read per request, in both positions (the package rule: no dead
 * knobs). The boot-time knobs are in BootKnobsOffTest and CustomisedTest.
 */
it('offers only whole days from 1 to max_days, and the check names the rest', function (): void {
    config()->set('trusted-devices.days', [30, 1, 7, 7, 365, 0, '3']);

    expect(Settings::days())->toBe([1, 7, 30])
        ->and(Settings::refusedDays())->toBe([365, 0, '3']);

    $this->artisan('trusted-devices:check')->expectsOutputToContain('outside 1 to 90')->assertFailed();

    config()->set('trusted-devices.max_days', 400);
    config()->set('trusted-devices.days', [1, 365]);

    expect(Settings::days())->toBe([1, 365])
        ->and(Settings::maxDays())->toBe(Settings::CEILING_DAYS);

    config()->set('trusted-devices.days', [1, 7, 30]);
    config()->set('trusted-devices.max_days', 90);

    $this->artisan('trusted-devices:check')->expectsOutputToContain('Ready.')->assertSuccessful();
});

it('asks everybody with a factor when no ability is set, and only the ability\'s holders when one is', function (): void {
    $member = Machines::member();
    $trustedDevices = resolve(TrustedDevices::class);

    config()->set('trusted-devices.ability', null);
    expect($trustedDevices->offeredTo($member))->toBeTrue();

    config()->set('trusted-devices.ability', 'admin');
    expect($trustedDevices->offeredTo($member))->toBeFalse();
});

it('offers nothing when the days list is empty', function (): void {
    config()->set('trusted-devices.days', []);

    expect(resolve(TrustedDevices::class)->offeredTo(Machines::admin()))->toBeFalse();
});

it('signs in with the configured guard', function (): void {
    config()->set('auth.guards.admins', ['driver' => 'session', 'provider' => 'users']);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    config()->set('trusted-devices.guard', 'admins');

    $this->withCookie('trusted_device', $cookie)->get('/home');

    expect(auth('admins')->id())->toBe($admin->getKey())
        ->and(auth('web')->check())->toBeFalse();
});

it('ends a trust on a password change only while the password is in the fingerprint', function (bool $withPassword): void {
    if (! $withPassword) {
        config()->set('trusted-devices.fingerprint', ['two_factor_secret', 'two_factor_confirmed_at']);
    }

    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $admin->forceFill(['password' => Hash::make('a-completely-new-password')])->save();

    $this->withCookie('trusted_device', $cookie)->get('/secret');

    expect(auth()->check())->toBe(! $withPassword);
})->with(['with the password' => [true], 'without it' => [false]]);

it('keeps the offer for offer_seconds', function (int $seconds, bool $kept): void {
    config()->set('trusted-devices.offer_seconds', $seconds);
    $admin = Machines::admin();

    $this->actingAs($admin)
        ->withSession(['trusted_devices.offer' => ['user' => (string) $admin->getKey(), 'at' => now()->getTimestamp() - 200, 'nonce' => 'n'.$seconds]])
        ->post(route('trusted-devices.store'), ['days' => '7']);

    expect(TrustedDevice::query()->exists())->toBe($kept);
})->with([[300, true], [120, false]]);

it('renders the configured question view, and the package page when it does not exist', function (string $view, string $rendered): void {
    View::addLocation(__DIR__.'/../views');
    config()->set('trusted-devices.views.question', $view);
    $admin = Machines::admin();

    $this->actingAs($admin)
        ->withSession(['trusted_devices.offer' => ['user' => (string) $admin->getKey(), 'at' => now()->getTimestamp(), 'nonce' => 'v']])
        ->get(route('trusted-devices.create'))
        ->assertViewIs($rendered);
})->with([
    'a host view' => ['custom-question', 'custom-question'],
    'a missing view' => ['no-such-view', 'trusted-devices::question'],
]);

it('asks after the challenge only while fortify.ask_after_challenge is on', function (bool $asks): void {
    config()->set('trusted-devices.fortify.ask_after_challenge', $asks);
    $admin = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);
    $location = (string) $this->post(route('two-factor.login.store'), ['code' => '123456'])->headers->get('Location');

    expect(str_contains($location, 'trust-this-device'))->toBe($asks);
})->with([[true], [false]]);

it('skips the challenge on a trusted device only while fortify.skip_challenge is on', function (bool $skips): void {
    config()->set('trusted-devices.fortify.skip_challenge', $skips);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);
    Machines::deviceFor($cookie)->forceFill(['signed_out_at' => now()])->save();

    $location = (string) $this->withCookie('trusted_device', $cookie)
        ->post(route('login.store'), ['email' => $admin->email, 'password' => 'password'])
        ->headers->get('Location');

    expect(str_contains($location, 'two-factor'))->toBe(! $skips);
})->with([[true], [false]]);
