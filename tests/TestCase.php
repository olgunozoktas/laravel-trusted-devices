<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Gate;
use Laravel\Fortify\Features;
use Laravel\Fortify\FortifyServiceProvider;
use Olgun\TrustedDevices\TrustedDevicesServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Workbench\App\Models\User;

/**
 * A Laravel app with Fortify's two-factor feature (confirm on), Laravel's users
 * table with Fortify's columns, an `admin` ability (an email at admin.test),
 * and two routes: `/secret` behind `auth`, `/home` open. Fortify's views are on,
 * so its named `login` and `two-factor.login` routes exist.
 */
abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [FortifyServiceProvider::class, TrustedDevicesServiceProvider::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('fortify.features', [Features::twoFactorAuthentication(['confirm' => true, 'confirmPassword' => false])]);
        $app['config']->set('fortify.home', '/home');
        $app['config']->set('fortify.views', true);
        $app['config']->set('trusted-devices.routes.home', '/home');
        // The shipped default is off (ConfigContractTest pins it); most tests are about the automatic sign-in.
        $app['config']->set('trusted-devices.auto_sign_in', true);

        Gate::define('admin', static fn (User $user): bool => str_ends_with((string) $user->email, '@admin.test'));
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../workbench/database/migrations');
    }

    /**
     * @param  Router  $router
     */
    protected function defineRoutes($router): void
    {
        $router->middleware(['web', 'auth'])->get('/secret', static fn (): string => 'secret')->name('secret');
        $router->middleware('web')->get('/home', static fn (): string => 'home')->name('home');
    }
}
