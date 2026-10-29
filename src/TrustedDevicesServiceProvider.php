<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\Contracts\RedirectsIfTwoFactorAuthenticatable;
use Laravel\Fortify\Contracts\TwoFactorLoginResponse;
use Olgun\TrustedDevices\Console\CheckCommand;
use Olgun\TrustedDevices\Console\SettleCommand;
use Olgun\TrustedDevices\Fortify\AskAfterChallenge;
use Olgun\TrustedDevices\Fortify\SkipChallengeOnTrustedDevice;
use Olgun\TrustedDevices\Http\Middleware\SignInFromTrustedDevice;
use Olgun\TrustedDevices\Support\Settings;
use Override;

/**
 * Wires the package into the host app. Each part has its knob in
 * `config/trusted-devices.php`; nothing here decides who may trust a device.
 */
final class TrustedDevicesServiceProvider extends ServiceProvider
{
    #[Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/trusted-devices.php', 'trusted-devices');
    }

    public function boot(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'trusted-devices');

        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/trusted-devices.php' => config_path('trusted-devices.php')], 'trusted-devices-config');
            $this->publishes([__DIR__.'/../resources/views' => resource_path('views/vendor/trusted-devices')], 'trusted-devices-views');
            $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'trusted-devices-migrations');
            $this->publishes([__DIR__.'/../resources/skills/laravel-trusted-devices' => base_path('.claude/skills/laravel-trusted-devices')], 'trusted-devices-skill');

            $this->commands([CheckCommand::class, SettleCommand::class]);
        }

        if (Settings::autoLoadMigrations()) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }

        if (Settings::routesEnabled() && ! $this->app->routesAreCached()) {
            Route::group([], __DIR__.'/../routes/trusted-devices.php');
        }

        $this->registerMiddleware();
        $this->stopAutoSignInOnLogout();
        $this->integrateFortify();
    }

    /**
     * Log out, by any route of the app: the device of that request stops
     * signing in by itself (the code stays skipped), or the next request would
     * sign the person straight back in.
     */
    private function stopAutoSignInOnLogout(): void
    {
        Event::listen([Logout::class, CurrentDeviceLogout::class], static function (Logout|CurrentDeviceLogout $event): void {
            app(TrustedDevices::class)->signOut(request(), $event->user);
        });
    }

    /**
     * In the `web` group, and before `auth` in the priority list: a guest on a
     * trusted device is signed in before `auth` would send them to the sign-in
     * page. The middleware itself reads `enabled` and `auto_sign_in` on each
     * request.
     */
    private function registerMiddleware(): void
    {
        $this->callAfterResolving(HttpKernel::class, static function (HttpKernel $kernel): void {
            if (! $kernel instanceof Kernel) {
                return;
            }

            $kernel->addToMiddlewarePriorityBefore(AuthenticatesRequests::class, SignInFromTrustedDevice::class);
            $kernel->appendMiddlewareToGroup('web', SignInFromTrustedDevice::class);
        });
    }

    /**
     * Both through the container's `extend()`, so an app's own bindings keep
     * working: the question DECORATES the app's two-factor login response, and
     * the challenge step is replaced only while it is still Fortify's own.
     */
    private function integrateFortify(): void
    {
        if (! interface_exists(TwoFactorLoginResponse::class)) {
            return;
        }

        $this->app->extend(TwoFactorLoginResponse::class, static fn (TwoFactorLoginResponse $inner, Application $app): TwoFactorLoginResponse => new AskAfterChallenge($inner, $app->make(TrustedDevices::class)));

        $this->app->extend(RedirectsIfTwoFactorAuthenticatable::class, static fn (RedirectsIfTwoFactorAuthenticatable $inner, Application $app): RedirectsIfTwoFactorAuthenticatable => $inner::class === RedirectIfTwoFactorAuthenticatable::class
            ? $app->make(SkipChallengeOnTrustedDevice::class)
            : $inner);
    }
}
