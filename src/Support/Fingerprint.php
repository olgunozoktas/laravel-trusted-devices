<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;

/**
 * What a trust was made against: the account and the columns in
 * `trusted-devices.fingerprint` (by default the password hash and the second
 * factor). Any of them changing ends every trust of that person, with no list of
 * places that must remember to revoke — the idea of Laravel's remember cookie
 * carrying the password hash.
 *
 * An HMAC with the application key, so the stored value says nothing about the
 * values it was made from. A date column is read as a timestamp: a column with
 * no cast is a string from the database and a date right after `forceFill(now())`,
 * and both must give the same fingerprint.
 */
final class Fingerprint
{
    public function of(Authenticatable $user): string
    {
        $identifier = $user->getAuthIdentifier();
        $parts = [is_scalar($identifier) ? (string) $identifier : ''];

        foreach (Settings::fingerprintColumns() as $column) {
            $parts[] = $this->normalise($column === 'password' ? $user->getAuthPassword() : $this->attribute($user, $column));
        }

        return hash_hmac('sha256', implode('|', $parts), config()->string('app.key'));
    }

    private function attribute(Authenticatable $user, string $column): mixed
    {
        return $user instanceof Model ? $user->getAttribute($column) : null;
    }

    private function normalise(mixed $value): string
    {
        return match (true) {
            $value instanceof DateTimeInterface => (string) $value->getTimestamp(),
            is_string($value) && $value !== '' && $this->looksLikeDate($value) => (string) Date::parse($value)->getTimestamp(),
            is_scalar($value) => (string) $value,
            default => '',
        };
    }

    private function looksLikeDate(string $value): bool
    {
        return preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/', $value) === 1;
    }
}
