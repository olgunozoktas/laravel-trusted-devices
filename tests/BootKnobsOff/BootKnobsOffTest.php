<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

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
