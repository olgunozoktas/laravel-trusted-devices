<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Tests\Support;

use Illuminate\Foundation\Application;
use Olgun\TrustedDevices\Tests\TestCase;

/**
 * The knobs read at boot, changed: a route prefix, a table name, a cookie name
 * and an explicit connection.
 */
abstract class CustomisedCase extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('trusted-devices.routes.prefix', 'account');
        $app['config']->set('trusted-devices.database.table', 'device_trusts');
        $app['config']->set('trusted-devices.database.connection', 'testing');
        $app['config']->set('trusted-devices.cookie.name', 'keep_me');
        $app['config']->set('trusted-devices.cookie.same_site', 'strict');
    }
}
