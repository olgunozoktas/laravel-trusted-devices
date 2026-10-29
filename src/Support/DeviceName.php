<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

/**
 * "Chrome on macOS": the words a page uses for a browser.
 *
 * The raw user agent never reaches a page: it is attacker-controlled, and a
 * crafted value would sit in a list of devices looking like a real one. Only
 * strings from the fixed lists below are ever shown.
 */
final class DeviceName
{
    private const array BROWSERS = [
        'Edg/' => 'Edge',
        'OPR/' => 'Opera',
        'Firefox/' => 'Firefox',
        'Chrome/' => 'Chrome',
        'Safari/' => 'Safari',
    ];

    private const array PLATFORMS = [
        'iPhone' => 'iPhone',
        'iPad' => 'iPad',
        'Android' => 'Android',
        'Macintosh' => 'macOS',
        'Mac OS X' => 'macOS',
        'Windows' => 'Windows',
        'Linux' => 'Linux',
    ];

    public static function describe(string $userAgent): string
    {
        if ($userAgent === '') {
            return 'Unknown device';
        }

        // Edge and Opera carry "Chrome/" too: the specific names come first.
        return sprintf('%s on %s', self::first(self::BROWSERS, $userAgent, 'Unknown browser'), self::first(self::PLATFORMS, $userAgent, 'Unknown device'));
    }

    /**
     * @param  array<string, string>  $names
     */
    private static function first(array $names, string $userAgent, string $fallback): string
    {
        foreach ($names as $needle => $name) {
            if (str_contains($userAgent, $needle)) {
                return $name;
            }
        }

        return $fallback;
    }
}
