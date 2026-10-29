<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Tests\Support;

use Illuminate\Foundation\Application;
use Olgun\TrustedDevices\Tests\TestCase;

/**
 * The knobs read at boot, in their OTHER position: no package routes, no
 * auto-loaded migrations.
 */
abstract class BootKnobsOffCase extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('trusted-devices.routes.enabled', false);
        $app['config']->set('trusted-devices.migrations.auto_load', false);
    }
}
