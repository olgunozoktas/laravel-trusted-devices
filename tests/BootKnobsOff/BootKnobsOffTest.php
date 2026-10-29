<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Olgun\TrustedDevices\Tests\Support\Machines;

/**
 * `routes.enabled` and `migrations.auto_load` off (their on position is every
 * other test file).
 */
it('registers no route and loads no migration, and the check names both', function (): void {
    expect(Route::has('trusted-devices.create'))->toBeFalse()
        ->and(Route::has('trusted-devices.destroy'))->toBeFalse()
        ->and(Schema::hasTable('trusted_devices'))->toBeFalse();

    config()->set('trusted-devices.routes.enabled', true);

    $this->artisan('trusted-devices:check')
        ->expectsOutputToContain('The table "trusted_devices" does not exist')
        ->expectsOutputToContain('The route trusted-devices.create is missing')
        ->assertFailed();
});

it('answers an accepted code with the app\'s own response, never an error, when there is no question route (F6)', function (): void {
    config()->set('trusted-devices.ability', null);
    $admin = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->post(route('two-factor.login.store'), ['code' => '123456'])->assertRedirect('/home');
    $this->artisan('trusted-devices:check')->expectsOutputToContain('the question is never asked');
});
