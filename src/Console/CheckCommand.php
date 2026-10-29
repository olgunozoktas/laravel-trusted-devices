<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Olgun\TrustedDevices\Http\Middleware\SignInFromTrustedDevice;
use Olgun\TrustedDevices\Support\Settings;
use ReflectionProperty;
use Throwable;

/**
 * Is this app ready for trusted devices? It reads the configuration, the
 * routes, the middleware and the table; it changes nothing. Exit 1 on a
 * failure, each with the exact next step.
 */
final class CheckCommand extends Command
{
    protected $signature = 'trusted-devices:check';

    protected $description = 'Check the trusted-device configuration, routes, middleware and table (reads only)';

    public function handle(): int
    {
        $failures = 0;

        $refused = Settings::refusedDays();
        if ($refused !== []) {
            $failures++;
            $this->components->error(sprintf('trusted-devices.days holds %s, outside 1 to %d (max_days): those are not offered. Fix config/trusted-devices.php.', implode(', ', array_map(static fn (mixed $day): string => is_scalar($day) ? (string) $day : get_debug_type($day), $refused)), Settings::maxDays()));
        } else {
            $this->components->info(Settings::days() === [] ? 'No days are offered: the question is off.' : sprintf('Offered: %s days (at most %d).', implode(', ', Settings::days()), Settings::maxDays()));
        }

        try {
            $hasTable = Schema::connection(Settings::connection())->hasTable(Settings::table());
        } catch (Throwable) {
            $hasTable = false;
        }

        if (! $hasTable) {
            $failures++;
            $this->components->error(sprintf('The table "%s" does not exist. Run: php artisan migrate', Settings::table()));
        }

        if (Settings::routesEnabled() && ! Route::has('trusted-devices.create')) {
            $failures++;
            $this->components->error('The route trusted-devices.create is missing although trusted-devices.routes.enabled is on.');
        }

        // Under Artisan the HTTP kernel is not resolved, so the app's `web`
        // group (and the package's place in it) does not exist yet.
        app(HttpKernel::class);
        $groups = app(Router::class)->getMiddlewareGroups();
        $web = is_array($groups['web'] ?? null) ? $groups['web'] : [];

        if (Settings::autoSignIn() && ! in_array(SignInFromTrustedDevice::class, $web, true)) {
            $failures++;
            $this->components->error('SignInFromTrustedDevice is not in the web group, so a trusted device does not sign in by itself.');
        }

        // A cookie the app does not encrypt could be written by anybody who can
        // set a cookie for the domain: the trust's secret must stay encrypted.
        $unencrypted = (new ReflectionProperty(EncryptCookies::class, 'neverEncrypt'))->getValue();

        if (is_array($unencrypted) && in_array(Settings::cookieName(), $unencrypted, true)) {
            $failures++;
            $this->components->error(sprintf('The cookie "%s" is on EncryptCookies\' exception list. Remove it from encryptCookies(except: [...]).', Settings::cookieName()));
        }

        $failures === 0 ? $this->components->info('Ready.') : $this->components->error(sprintf('%d problem(s).', $failures));

        return $failures === 0 ? self::SUCCESS : self::FAILURE;
    }
}
