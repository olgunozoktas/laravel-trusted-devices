<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Olgun\TrustedDevices\TrustedDeviceList;

/**
 * Seeing and ending a person's own trusts, and the two commands. The refusals
 * that matter: another account's device cannot be forgotten, and the list
 * never carries the hash, the fingerprint, the address or an integer id.
 */
beforeEach(function (): void {
    config()->set('trusted-devices.ability', 'admin');
});

function requestWithCookie(string $cookie): Request
{
    return Request::create('/', 'GET', cookies: ['trusted_device' => $cookie]);
}

it('lists the live trusts with no secret in them', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);

    $rows = resolve(TrustedDeviceList::class)->for(requestWithCookie($cookie), $admin);

    expect($rows)->toHaveCount(1)
        ->and($rows[0])->toHaveKeys(['uuid', 'device', 'is_current', 'signs_in', 'until', 'until_at', 'last_used'])
        ->and($rows[0])->not->toHaveKeys(['id', 'token_hash', 'fingerprint', 'ip_address', 'user_id'])
        ->and($rows[0]['is_current'])->toBeTrue()
        ->and($rows[0]['device'])->toBe('Chrome on macOS');
});

it('does not list a trust that a new password ended', function (): void {
    $admin = Machines::admin();
    Machines::trust($admin);

    $admin->forceFill(['password' => Hash::make('a-completely-new-password')])->save();

    expect(resolve(TrustedDeviceList::class)->for(Request::create('/'), $admin))->toBe([]);
});

it('forgets a device, softly, and that device then signs nobody in', function (): void {
    $admin = Machines::admin();
    $cookie = Machines::trust($admin);
    $device = Machines::deviceFor($cookie);

    $this->actingAs($admin)->delete(route('trusted-devices.destroy', ['uuid' => $device->uuid]))
        ->assertSessionHas('trusted-devices.status', 'forgotten');

    $this->assertSoftDeleted($device);

    auth()->guard('web')->logout();
    $this->withCookie('trusted_device', $cookie)->get('/secret');

    $this->assertGuest();
});

it("cannot forget another account's device, and answers 404 for a non-uuid", function (): void {
    $device = Machines::deviceFor(Machines::trust(Machines::admin()));

    $this->actingAs(Machines::admin())->delete(route('trusted-devices.destroy', ['uuid' => $device->uuid]))
        ->assertSessionHas('trusted-devices.status', 'already-forgotten');
    $this->actingAs(Machines::admin())->delete('/trusted-devices/1')->assertNotFound();

    expect($device->refresh()->trashed())->toBeFalse();
});

it('forgets the others and keeps this device; stops the others signing in and keeps them', function (): void {
    $admin = Machines::admin();
    $other = Machines::deviceFor(Machines::trust($admin));
    $thisCookie = Machines::trust($admin);
    $list = resolve(TrustedDeviceList::class);

    expect($list->stopOthersSigningIn(requestWithCookie($thisCookie), $admin))->toBe(1)
        ->and($other->refresh()->signed_out_at)->not->toBeNull()
        ->and(Machines::deviceFor($thisCookie)->signed_out_at)->toBeNull();

    expect($list->forgetOthers(requestWithCookie($thisCookie), $admin))->toBe(1);

    $this->assertSoftDeleted($other);
    expect(Machines::deviceFor($thisCookie)->trashed())->toBeFalse();
});

it('keeps at most max_per_user live trusts, in both positions of the knob', function (int $max): void {
    config()->set('trusted-devices.max_per_user', $max);
    $admin = Machines::admin();

    foreach (range(1, 4) as $ignored) {
        Machines::trust($admin);
    }

    expect(TrustedDevice::query()->count())->toBe(min(4, $max));
})->with([2, 10]);

it('settles: forgets the trusts of every person who may no longer hold one, and only theirs', function (): void {
    $keeps = Machines::admin();
    $loses = Machines::admin();
    $kept = Machines::deviceFor(Machines::trust($keeps));
    $lost = Machines::deviceFor(Machines::trust($loses));

    Gate::define('admin', static fn ($user): bool => $user->getKey() === $keeps->getKey());

    $this->artisan('trusted-devices:settle')->assertSuccessful();

    $this->assertSoftDeleted($lost);
    expect($kept->refresh()->trashed())->toBeFalse();
});
