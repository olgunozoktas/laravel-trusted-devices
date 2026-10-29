<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie as Cookies;
use Illuminate\Support\Str;

/**
 * The cookie that names a trusted device: `<uuid>|<secret>`.
 *
 * Encrypted by the app's `EncryptCookies` (keep its name off that middleware's
 * exception list), HttpOnly so no script reads it, Secure wherever the session
 * cookie is, and SameSite `trusted-devices.cookie.same_site` (lax by default) so
 * a cross-site form post does not carry it. The path and the domain are the
 * session cookie's.
 */
final class Cookie
{
    public function has(Request $request): bool
    {
        return $request->cookies->has(Settings::cookieName());
    }

    /**
     * @return array{uuid: string, secret: string}|null
     */
    public function read(Request $request): ?array
    {
        $value = $request->cookie(Settings::cookieName());

        if (! is_string($value) || ! str_contains($value, '|')) {
            return null;
        }

        [$uuid, $secret] = explode('|', $value, 2);

        if (! Str::isUuid($uuid) || $secret === '') {
            return null;
        }

        return ['uuid' => $uuid, 'secret' => $secret];
    }

    public function queue(string $uuid, string $secret, int $days): void
    {
        Cookies::queue(Settings::cookieName(), $uuid.'|'.$secret, $days * 24 * 60, $this->path(), $this->domain(), $this->secure(), true, false, Settings::cookieSameSite());
    }

    public function forget(): void
    {
        Cookies::queue(Cookies::forget(Settings::cookieName(), $this->path(), $this->domain()));
    }

    private function path(): string
    {
        $path = config('session.path', '/');

        return is_string($path) && $path !== '' ? $path : '/';
    }

    private function domain(): ?string
    {
        $domain = config('session.domain');

        return is_string($domain) && $domain !== '' ? $domain : null;
    }

    private function secure(): ?bool
    {
        $secure = config('session.secure');

        return is_bool($secure) ? $secure : null;
    }
}
