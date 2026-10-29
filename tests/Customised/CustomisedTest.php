<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Workbench\App\Models\User;

/**
 * `routes.prefix`, `database.table`, `database.connection`, `cookie.name` and
 * `cookie.same_site` changed (their default position is every other file).
 */
it('serves the question under the prefix, keeps trusts in the named table and reads the named cookie', function (): void {
    expect(route('trusted-devices.create', absolute: false))->toBe('/account/trust-this-device')
        ->and(Schema::hasTable('device_trusts'))->toBeTrue()
        ->and(Schema::hasTable('trusted_devices'))->toBeFalse();

    $admin = Machines::admin();
    $offer = ['trusted_devices.offer' => ['user' => (string) $admin->getKey(), 'at' => now()->getTimestamp(), 'nonce' => 'n']];

    $response = $this->actingAs($admin)->withSession($offer)->post('/account/trust-this-device', ['days' => '7']);

    $cookie = $response->getCookie('keep_me', decrypt: false);

    expect($cookie)->not->toBeNull()
        ->and($cookie?->getSameSite())->toBe('strict')
        ->and(TrustedDevice::query()->count())->toBe(1)
        ->and((new TrustedDevice)->getTable())->toBe('device_trusts');

    auth()->guard('web')->logout();
    $value = (string) $response->getCookie('keep_me')?->getValue();

    $this->withCookie('keep_me', $value)->get('/secret')->assertOk();
    $this->assertAuthenticatedAs(User::query()->findOrFail($admin->getKey()));
});
