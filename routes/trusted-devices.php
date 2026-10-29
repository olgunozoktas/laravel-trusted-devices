<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Olgun\TrustedDevices\Http\Controllers\TrustedDeviceController;
use Olgun\TrustedDevices\Support\Settings;

/*
 * The question after a code, its answer (throttled), and Forget (scoped to the
 * signed-in person). Prefix and middleware: `trusted-devices.routes`.
 */
Route::middleware(Settings::routeMiddleware())
    ->prefix(Settings::routePrefix())
    ->name('trusted-devices.')
    ->group(function (): void {
        Route::get('trust-this-device', [TrustedDeviceController::class, 'create'])->name('create');
        Route::post('trust-this-device', [TrustedDeviceController::class, 'store'])->middleware('throttle:6,1')->name('store');
        Route::delete('trusted-devices/{uuid}', [TrustedDeviceController::class, 'destroy'])->name('destroy');
    });
