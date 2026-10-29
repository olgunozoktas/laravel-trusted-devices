<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\Fortify;
use Olgun\TrustedDevices\Events\TrustedDeviceCreated;
use Olgun\TrustedDevices\Events\TrustedDeviceForgotten;
use Olgun\TrustedDevices\Events\TrustedDeviceUsed;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Offer;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Olgun\TrustedDevices\TrustedDevices;
use Workbench\App\Models\User;

/**
 * The independent review of 2026-10-30: each test here kills a mutation that the
 * first 56 tests let through, or proves a finding fixed (F1 to F9).
 */
beforeEach(function (): void {
    config()->set('trusted-devices.ability', 'admin');
});

it('refuses a wrong password on a trusted device, and never lets it reach the challenge on another (M14)', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);
    Machines::deviceFor($cookie)->forceFill(['signed_out_at' => now()])->save();

    $this->withCookie('trusted_device', $cookie)
        ->post(route('login.store'), ['email' => $admin->email, 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->assertGuest();

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'wrong'])->assertSessionHasErrors('email');
    expect(session('login.id'))->toBeNull();
});

it('keeps a signed-in person who carries another trusted cookie (M16)', function (): void {
    $cookie = Machines::trust(Machines::admin());
    $other = Machines::admin();

    $this->actingAs($other)->withCookie('trusted_device', $cookie)->get('/secret')->assertOk();

    $this->assertAuthenticatedAs($other);
});

it('signs in by itself with no remember-me cookie (M37)', function (): void {
    $cookie = Machines::trust(Machines::admin());

    $response = $this->withCookie('trusted_device', $cookie)->get('/secret');

    expect(collect($response->headers->getCookies())->filter(fn ($c): bool => str_starts_with($c->getName(), 'remember_'))->all())->toBe([]);
});

it('sets an HttpOnly cookie and never SameSite none (M21, M22)', function (): void {
    config()->set('trusted-devices.cookie.same_site', 'none');
    $admin = Machines::admin();

    $cookie = $this->actingAs($admin)
        ->withSession(['trusted_devices.offer' => ['user' => (string) $admin->getKey(), 'at' => now()->getTimestamp(), 'nonce' => 'm21']])
        ->post(route('trusted-devices.store'), ['days' => '7'])
        ->getCookie('trusted_device', decrypt: false);

    expect($cookie?->isHttpOnly())->toBeTrue()->and($cookie?->getSameSite())->toBe('lax');
});

it('drops a bad cookie on the session path and domain (M39)', function (): void {
    config()->set('session.domain', 'app.test');
    [$uuid] = explode('|', Machines::trust(Machines::admin()));

    $cookie = $this->withCookie('trusted_device', $uuid.'|'.str_repeat('x', 64))->get('/secret')->getCookie('trusted_device', decrypt: false);

    expect($cookie?->getDomain())->toBe('app.test')->and($cookie?->getPath())->toBe('/')->and($cookie?->isCleared())->toBeTrue();
});

it('takes no Log out of nobody, of another guard, or of another person as this device\'s (F2, M12)', function (): void {
    config()->set('auth.guards.admins', ['driver' => 'session', 'provider' => 'users']);
    $owner = Machines::admin();
    $cookie = Machines::trust($owner);
    $other = Machines::admin();

    // Dispatched directly: Pest's `not->toThrow(<an interface>)` passes even when the call throws (the review's round 3).
    event(new Logout('web', null));

    Route::middleware('web')->post('/admins-logout', static function () use ($owner): string {
        auth('admins')->login(User::query()->findOrFail($owner->getKey()));
        auth('admins')->logout();

        return 'ok';
    });
    $this->withCookie('trusted_device', $cookie)->post('/admins-logout');
    $this->actingAs($other)->withCookie('trusted_device', $cookie)->post(route('logout'));

    expect(Machines::deviceFor($cookie)->signed_out_at)->toBeNull();
});

it('refuses the automatic sign-in while Fortify::authenticateUsing is set, unless the app opts in (F1)', function (bool $optIn): void {
    config()->set('trusted-devices.auto_sign_in_with_authenticate_using', $optIn);
    $cookie = Machines::trust(Machines::admin());

    try {
        Fortify::authenticateUsing(static fn () => null);
        $this->withCookie('trusted_device', $cookie)->get('/home');

        expect(Auth::check())->toBe($optIn);
    } finally {
        Fortify::$authenticateUsingCallback = null;
    }
})->with(['refused' => [false], 'the opt-in' => [true]]);

it('ends no trust while switched off, and settle ends none while off (F3)', function (string $how): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);
    match ($how) {
        'enabled off' => config()->set('trusted-devices.enabled', false),
        'days empty' => config()->set('trusted-devices.days', []),
    };

    $this->withCookie('trusted_device', $cookie)->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);
    $this->artisan('trusted-devices:settle')->assertSuccessful();

    expect(Machines::deviceFor($cookie)->trashed())->toBeFalse();
})->with(['enabled off', 'days empty']);

it('refuses to make a trust through the API for a person who may not be asked (M4)', function (): void {
    $member = Machines::member();
    resolve(Offer::class)->put($member);

    expect(resolve(TrustedDevices::class)->trust(Request::create('/'), $member, 7))->toBeNull();
});

it('does not challenge an unconfirmed factor while Fortify confirms (M15)', function (): void {
    $admin = Machines::admin();
    $admin->forceFill(['two_factor_confirmed_at' => null])->save();

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->assertAuthenticatedAs($admin);
});

it('does not ask again on a device that already trusts the person (M20)', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $request = Request::create('/', cookies: ['trusted_device' => $cookie]);

    expect(resolve(TrustedDevices::class)->offerAfterCode($request, $admin))->toBeFalse();
});

it("keeps another person's trust when a second person trusts the same browser (M27)", function (): void {
    $first = Machines::admin();
    $cookie = Machines::trust($first);
    $second = Machines::admin();

    $this->actingAs($second)->withCookie('trusted_device', $cookie)
        ->withSession(['trusted_devices.offer' => ['user' => (string) $second->getKey(), 'at' => now()->getTimestamp(), 'nonce' => 'm27']])
        ->post(route('trusted-devices.store'), ['days' => '7']);

    expect(Machines::deviceFor($cookie)->trashed())->toBeFalse()
        ->and(TrustedDevice::query()->count())->toBe(2);
});

it('throttles the answer (M28)', function (): void {
    $admin = Machines::admin();

    foreach (range(1, 6) as $ignored) {
        $this->actingAs($admin)->post(route('trusted-devices.store'), ['days' => '7']);
    }

    $this->actingAs($admin)->post(route('trusted-devices.store'), ['days' => '7'])->assertTooManyRequests();
});

it('resumes the automatic sign-in after a code sign-in on a trusted device (F9)', function (): void {
    config()->set('trusted-devices.fortify.skip_challenge', false);
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);
    Machines::deviceFor($cookie)->forceFill(['signed_out_at' => now()])->save();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->withCookie('trusted_device', $cookie)->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);
    $this->withCookie('trusted_device', $cookie)->post(route('two-factor.login.store'), ['code' => '123456']);

    expect(Machines::deviceFor($cookie)->signed_out_at)->toBeNull();
});

it("leaves another person's signed-out device signed out after a code sign-in on it (F9, the review's R2b)", function (): void {
    $owner = Machines::admin();
    $cookie = Machines::trust($owner);
    Machines::deviceFor($cookie)->forceFill(['signed_out_at' => now()])->save();
    $other = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->withCookie('trusted_device', $cookie)->post(route('login.store'), ['email' => $other->email, 'password' => 'password'])
        ->assertRedirect(route('two-factor.login'));
    $this->withCookie('trusted_device', $cookie)->post(route('two-factor.login.store'), ['code' => '123456']);

    $this->assertAuthenticatedAs($other);
    expect(Machines::deviceFor($cookie)->signed_out_at)->not->toBeNull();
});

it('sends an Inertia request to the question as a full visit (F8)', function (): void {
    $admin = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->withHeader('X-Inertia', 'true')->post(route('two-factor.login.store'), ['code' => '123456'])
        ->assertStatus(409)->assertHeader('X-Inertia-Location', route('trusted-devices.create'));
});

it('queues an event with the models by key, never the hashes (F7)', function (): void {
    $admin = Machines::admin();
    $device = Machines::deviceFor(Machines::trust($admin));

    foreach ([
        new TrustedDeviceCreated($admin, $device, 7, '203.0.113.7'),
        new TrustedDeviceUsed($admin, $device, TrustedDeviceUsed::AUTO_SIGN_IN, '203.0.113.7'),
        new TrustedDeviceForgotten($admin, $device, TrustedDeviceForgotten::FORGOTTEN),
    ] as $event) {
        $payload = serialize($event);

        expect($payload)->not->toContain($device->token_hash)
            ->and($payload)->not->toContain((string) $admin->getAuthPassword())
            ->and($payload)->not->toContain($device->fingerprint);
    }
});
