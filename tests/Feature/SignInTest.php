<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Olgun\TrustedDevices\Events\TrustedDeviceForgotten;
use Olgun\TrustedDevices\Events\TrustedDeviceUsed;
use Olgun\TrustedDevices\Http\Middleware\SignInFromTrustedDevice;
use Olgun\TrustedDevices\Tests\Support\Machines;

/**
 * What a trusted device does: it signs its person in by itself, and a password
 * sign-in on it skips Fortify's challenge — until the trust ends, is forgotten,
 * or no longer describes the account. Every "it works" has its "and not
 * otherwise", because a cookie that signs in everybody passes the first half.
 */
beforeEach(function (): void {
    config()->set('trusted-devices.ability', 'admin');
});

it('signs a guest in by itself on a trusted device, and fires the event', function (): void {
    Event::fake([TrustedDeviceUsed::class]);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $this->withCookie('trusted_device', $cookie)->get('/secret')->assertOk();

    $this->assertAuthenticatedAs($admin);
    Event::assertDispatched(TrustedDeviceUsed::class, fn (TrustedDeviceUsed $event): bool => $event->how === TrustedDeviceUsed::AUTO_SIGN_IN);
});

it('leaves a guest with no cookie signed out', function (): void {
    Machines::trust(Machines::admin());

    $this->get('/secret')->assertRedirect(route('login'));

    $this->assertGuest();
});

it('signs nobody in with a tampered secret, and drops the cookie', function (): void {
    [$uuid] = explode('|', Machines::trust(Machines::admin()));

    $this->withCookie('trusted_device', $uuid.'|'.str_repeat('x', 64))->get('/secret')->assertCookieExpired('trusted_device');

    $this->assertGuest();
});

it('signs nobody in after the chosen days end', function (): void {
    $cookie = Machines::trust(Machines::admin(), days: 7);

    $this->travel(7)->days();
    $this->travel(1)->minutes();

    $this->withCookie('trusted_device', $cookie)->get('/secret');

    $this->assertGuest();
});

it('ends the trust for good when the account no longer fits it', function (string $change): void {
    Event::fake([TrustedDeviceForgotten::class]);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    match ($change) {
        'password' => $admin->forceFill(['password' => Hash::make('a-completely-new-password')])->save(),
        'factor' => $admin->forceFill(['two_factor_confirmed_at' => now()->addMinute()])->save(),
        'ability' => Gate::define('admin', static fn (): bool => false),
    };

    $this->withCookie('trusted_device', $cookie)->get('/secret');

    $this->assertGuest();
    $this->assertSoftDeleted(Machines::deviceFor($cookie));
    Event::assertDispatched(TrustedDeviceForgotten::class, fn (TrustedDeviceForgotten $event): bool => $event->reason === TrustedDeviceForgotten::NO_LONGER_FITS);
})->with(['password', 'factor', 'ability']);

it('does not revive a trust when the ability comes back', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    Gate::define('admin', static fn (): bool => false);
    $this->withCookie('trusted_device', $cookie)->get('/secret');

    Gate::define('admin', static fn (): bool => true);
    $this->withCookie('trusted_device', $cookie)->get('/secret');

    $this->assertGuest();
});

it('stops signing in by itself after Log out, and starts again after a password sign-in with no code', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $this->withCookie('trusted_device', $cookie)->get('/secret');
    $this->assertAuthenticatedAs($admin);

    $this->post(route('logout'));
    $this->get('/secret')->assertRedirect(route('login'));
    $this->assertGuest();
    expect(Machines::deviceFor($cookie)->signed_out_at)->not->toBeNull();

    $signIn = $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    expect($signIn->headers->get('Location'))->not->toContain('two-factor');
    $this->assertAuthenticatedAs($admin);
    expect(Machines::deviceFor($cookie)->signed_out_at)->toBeNull();
});

it('asks for the code at sign-in on a device that is not trusted', function (): void {
    $admin = Machines::admin();

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password'])->assertRedirect(route('two-factor.login'));

    $this->assertGuest();
});

it('asks another account for its code on a device trusted for somebody else, and leaves that trust alone', function (): void {
    $first = Machines::admin();
    $cookie = Machines::trust($first);
    Machines::deviceFor($cookie)->forceFill(['signed_out_at' => now()])->save();

    $second = Machines::admin();

    $this->withCookie('trusted_device', $cookie)
        ->post(route('login.store'), ['email' => $second->email, 'password' => 'password'])
        ->assertRedirect(route('two-factor.login'));

    $this->assertGuest();
    expect(Machines::deviceFor($cookie)->trashed())->toBeFalse();
});

it('only skips the code, and never signs in by itself, with auto_sign_in off', function (): void {
    config()->set('trusted-devices.auto_sign_in', false);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $this->withCookie('trusted_device', $cookie)->get('/secret')->assertRedirect(route('login'));
    $this->assertGuest();

    $this->withCookie('trusted_device', $cookie)
        ->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->assertAuthenticatedAs($admin);
});

it('does nothing at all while switched off', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    config()->set('trusted-devices.enabled', false);

    $this->withCookie('trusted_device', $cookie)->get('/secret')->assertRedirect(route('login'));
    $this->withCookie('trusted_device', $cookie)
        ->post(route('login.store'), ['email' => $admin->email, 'password' => 'password'])
        ->assertRedirect(route('two-factor.login'));
});

it('signs in after the session starts and before `auth`', function (): void {
    // A real app resolves the HTTP kernel before its providers boot (public/index.php);
    // Testbench resolves it at the first request, so this test resolves it first.
    resolve(HttpKernel::class);

    $groups = resolve(Router::class)->getMiddlewareGroups();
    $priority = resolve(Router::class)->middlewarePriority;

    expect($groups['web'] ?? [])->toContain(SignInFromTrustedDevice::class);

    $position = array_search(SignInFromTrustedDevice::class, $priority, true);

    expect($position)->toBeInt()
        ->and($position)->toBeLessThan(array_search(AuthenticatesRequests::class, $priority, true))
        ->and($position)->toBeGreaterThan(array_search(StartSession::class, $priority, true));
});
