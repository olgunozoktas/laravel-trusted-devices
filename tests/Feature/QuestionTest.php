<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Olgun\TrustedDevices\Events\TrustedDeviceCreated;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Offer;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Olgun\TrustedDevices\TrustedDevices;
use Workbench\App\Models\User;

/**
 * "Keep me signed in on this machine?" — when it is asked, and what its answer
 * may make. The refusal that matters most: a trust is made ONLY with a fresh,
 * one-time offer, so a stolen session cookie cannot trust a device for itself.
 */
beforeEach(function (): void {
    config()->set('trusted-devices.ability', 'admin');
});

/**
 * @return array<string, array<string, int|string>>
 */
function offerFor(User $user, string $nonce = 'nonce-of-this-test', int $age = 0): array
{
    return ['trusted_devices.offer' => ['user' => (string) $user->getKey(), 'at' => now()->getTimestamp() - $age, 'nonce' => $nonce]];
}

it("asks after Fortify's two-factor challenge, to a person who passes the ability only", function (string $who, bool $asked): void {
    $user = $who === 'admin' ? Machines::admin() : Machines::member();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $user->email, 'password' => 'password'])->assertRedirect(route('two-factor.login'));
    $response = $this->post(route('two-factor.login.store'), ['code' => '123456']);

    $this->assertAuthenticatedAs($user);

    if ($asked) {
        $response->assertRedirect(route('trusted-devices.create'));
    } else {
        expect($response->headers->get('Location'))->not->toContain('trust-this-device');
    }
})->with([
    'an admin' => ['admin', true],
    'a member' => ['member', false],
]);

it('shows the question with the choices while the offer is fresh', function (): void {
    $admin = Machines::admin();

    $this->actingAs($admin)->withSession(offerFor($admin))->get(route('trusted-devices.create'))
        ->assertOk()->assertViewIs('trusted-devices::question')->assertViewHas('choices', [1, 7, 30]);
});

it('tells the page whether the device will sign in by itself', function (bool $autoSignIn): void {
    config()->set('trusted-devices.auto_sign_in', $autoSignIn);
    $admin = Machines::admin();

    $this->actingAs($admin)->withSession(offerFor($admin))->get(route('trusted-devices.create'))
        ->assertViewHas('autoSignIn', $autoSignIn);
})->with([[true], [false]]);

it('does not show the question without an offer', function (): void {
    $this->actingAs(Machines::admin())->get(route('trusted-devices.create'))->assertRedirect('/home');
});

it('trusts the device for the chosen days, sets the cookie, keeps only the hash and fires the event', function (): void {
    Event::fake([TrustedDeviceCreated::class]);
    $admin = Machines::admin();

    $response = $this->actingAs($admin)->withSession(offerFor($admin))->withHeader('User-Agent', Machines::AGENT)
        ->post(route('trusted-devices.store'), ['days' => '7']);

    $response->assertRedirect('/home')->assertCookie('trusted_device');

    $device = TrustedDevice::query()->sole();
    $secret = explode('|', (string) $response->getCookie('trusted_device')?->getValue())[1] ?? '';

    expect($device->user_id)->toBe((string) $admin->getKey())
        ->and($device->name)->toBe('Chrome on macOS')
        ->and($device->expires_at->isSameDay(now()->addDays(7)))->toBeTrue()
        ->and($device->token_hash)->toBe(hash('sha256', $secret))->not->toBe($secret);

    Event::assertDispatched(TrustedDeviceCreated::class, fn (TrustedDeviceCreated $event): bool => $event->days === 7);
});

it("makes no trust without an offer, with an old one, with another account's, or with one without a nonce", function (string $case): void {
    $admin = Machines::admin();
    $other = Machines::admin();

    $session = match ($case) {
        'none' => [],
        'old' => offerFor($admin, age: 121),
        'other' => offerFor($other),
        'no nonce' => ['trusted_devices.offer' => ['user' => (string) $admin->getKey(), 'at' => now()->getTimestamp()]],
    };

    $this->actingAs($admin)->withSession($session)->post(route('trusted-devices.store'), ['days' => '7'])
        ->assertCookieMissing('trusted_device');

    expect(TrustedDevice::query()->count())->toBe(0);
})->with(['none', 'old', 'other', 'no nonce']);

it('spends one offer once, even when the same offer arrives twice', function (): void {
    $admin = Machines::admin();

    $this->actingAs($admin)->withSession(offerFor($admin, 'one'))->post(route('trusted-devices.store'), ['days' => '7']);
    $this->actingAs($admin)->withSession(offerFor($admin, 'one'))->post(route('trusted-devices.store'), ['days' => '30']);

    expect(TrustedDevice::query()->count())->toBe(1);
});

it('refuses days that are not offered, and a person who may not be asked', function (): void {
    $admin = Machines::admin();
    $member = Machines::member();

    $this->actingAs($admin)->withSession(offerFor($admin))->post(route('trusted-devices.store'), ['days' => '365'])->assertSessionHasErrors('days');
    $this->actingAs($member)->withSession(offerFor($member))->post(route('trusted-devices.store'), ['days' => '7'])->assertForbidden();

    expect(TrustedDevice::query()->count())->toBe(0);
});

it('takes "No, ask every time" and does not ask again in this session', function (): void {
    $admin = Machines::admin();

    $this->actingAs($admin)->withSession(offerFor($admin))->post(route('trusted-devices.store'), ['days' => 'never'])
        ->assertRedirect('/home')->assertCookieMissing('trusted_device');

    expect(resolve(Offer::class)->isDeclinedBy($admin))->toBeTrue()
        ->and(TrustedDevice::query()->count())->toBe(0);
});

it('never asks somebody with no confirmed factor', function (): void {
    expect(resolve(TrustedDevices::class)->offeredTo(Machines::withoutFactor()))->toBeFalse();
});
