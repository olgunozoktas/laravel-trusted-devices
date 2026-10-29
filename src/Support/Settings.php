<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

/**
 * The ONE reader of `config/trusted-devices.php`.
 *
 * Every class asks here, so a key is honoured everywhere it claims to govern,
 * and a wrong value is narrowed in one place (a string where a list belongs
 * reads as the safe default, never as a crash or an open door).
 */
final class Settings
{
    /**
     * The hard ceiling on `max_days`: a configuration cannot trust a device for
     * longer than a year.
     */
    public const int CEILING_DAYS = 365;

    public static function enabled(): bool
    {
        return (bool) config('trusted-devices.enabled', true);
    }

    /**
     * The offered days, smallest first: whole numbers from 1 to max_days.
     *
     * @return list<int>
     */
    public static function days(): array
    {
        $max = self::maxDays();

        $days = array_values(array_unique(array_filter(
            (array) config('trusted-devices.days', []),
            static fn (mixed $day): bool => is_int($day) && $day >= 1 && $day <= $max,
        )));

        sort($days);

        return $days;
    }

    /**
     * Values of `days` that are not offered (outside 1..max_days, or not whole
     * numbers): what `trusted-devices:check` names.
     *
     * @return list<mixed>
     */
    public static function refusedDays(): array
    {
        $max = self::maxDays();

        return array_values(array_filter(
            (array) config('trusted-devices.days', []),
            static fn (mixed $day): bool => ! is_int($day) || $day < 1 || $day > $max,
        ));
    }

    public static function maxDays(): int
    {
        $max = config('trusted-devices.max_days', 90);

        return is_int($max) ? max(1, min($max, self::CEILING_DAYS)) : 90;
    }

    public static function ability(): ?string
    {
        $ability = config('trusted-devices.ability');

        return is_string($ability) && $ability !== '' ? $ability : null;
    }

    public static function guard(): string
    {
        $guard = config('trusted-devices.guard', 'web');

        return is_string($guard) && $guard !== '' ? $guard : 'web';
    }

    public static function autoSignIn(): bool
    {
        return (bool) config('trusted-devices.auto_sign_in', true);
    }

    /**
     * @return list<string>
     */
    public static function fingerprintColumns(): array
    {
        $columns = config('trusted-devices.fingerprint', ['password', 'two_factor_secret', 'two_factor_confirmed_at']);

        return array_values(array_filter((array) $columns, static fn (mixed $column): bool => is_string($column) && $column !== ''));
    }

    public static function offerSeconds(): int
    {
        $seconds = config('trusted-devices.offer_seconds', 120);

        return is_int($seconds) && $seconds > 0 ? $seconds : 120;
    }

    public static function maxPerUser(): int
    {
        $max = config('trusted-devices.max_per_user', 10);

        return is_int($max) && $max > 0 ? $max : 10;
    }

    public static function cookieName(): string
    {
        $name = config('trusted-devices.cookie.name', 'trusted_device');

        return is_string($name) && $name !== '' ? $name : 'trusted_device';
    }

    public static function cookieSameSite(): string
    {
        $sameSite = config('trusted-devices.cookie.same_site', 'lax');

        return in_array($sameSite, ['lax', 'strict'], true) ? $sameSite : 'lax';
    }

    public static function routesEnabled(): bool
    {
        return (bool) config('trusted-devices.routes.enabled', true);
    }

    public static function routePrefix(): string
    {
        $prefix = config('trusted-devices.routes.prefix', '');

        return is_string($prefix) ? trim($prefix, '/') : '';
    }

    /**
     * @return list<string>
     */
    public static function routeMiddleware(): array
    {
        $middleware = config('trusted-devices.routes.middleware', ['web', 'auth']);

        return array_values(array_filter((array) $middleware, static fn (mixed $entry): bool => is_string($entry) && $entry !== ''));
    }

    public static function home(): string
    {
        $home = config('trusted-devices.routes.home', '/');

        return is_string($home) && $home !== '' ? $home : '/';
    }

    public static function questionView(): string
    {
        $view = config('trusted-devices.views.question', 'trusted-devices::question');

        return is_string($view) && $view !== '' ? $view : 'trusted-devices::question';
    }

    public static function connection(): ?string
    {
        $connection = config('trusted-devices.database.connection');

        return is_string($connection) && $connection !== '' ? $connection : null;
    }

    public static function table(): string
    {
        $table = config('trusted-devices.database.table', 'trusted_devices');

        return is_string($table) && $table !== '' ? $table : 'trusted_devices';
    }

    public static function autoLoadMigrations(): bool
    {
        return (bool) config('trusted-devices.migrations.auto_load', true);
    }

    public static function fortifyAsksAfterChallenge(): bool
    {
        return (bool) config('trusted-devices.fortify.ask_after_challenge', true);
    }

    public static function fortifySkipsChallenge(): bool
    {
        return (bool) config('trusted-devices.fortify.skip_challenge', true);
    }
}
