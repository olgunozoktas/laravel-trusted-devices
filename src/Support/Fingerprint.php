<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

use BackedEnum;
use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;
use JsonSerializable;
use LogicException;
use Stringable;
use UnitEnum;

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
 * and both must give the same fingerprint (a date string is read in
 * `app.timezone`, so a change of it ends every trust, which fails closed). An
 * enum is read as its value, an array or a JSON value as its JSON.
 */
final class Fingerprint
{
    public function of(Authenticatable $user): string
    {
        $identifier = $user->getAuthIdentifier();
        $parts = [is_scalar($identifier) ? (string) $identifier : ''];

        foreach (Settings::fingerprintColumns() as $column) {
            $parts[] = $this->normalise($column, $column === 'password' ? $user->getAuthPassword() : $this->attribute($user, $column));
        }

        // A JSON list, never a string joined with a separator: two different
        // lists can never give the same input.
        return hash_hmac('sha256', (string) json_encode($parts, JSON_THROW_ON_ERROR), config()->string('app.key'));
    }

    private function attribute(Authenticatable $user, string $column): mixed
    {
        return $user instanceof Model ? $user->getAttribute($column) : null;
    }

    /**
     * One value of one column, as a string. A column cast to something this
     * cannot read is refused, never read as "" (a change of it would then never
     * end a trust).
     */
    private function normalise(string $column, mixed $value): string
    {
        return match (true) {
            $value === null => '',
            $value instanceof DateTimeInterface => (string) $value->getTimestamp(),
            $value instanceof BackedEnum => (string) $value->value,
            $value instanceof UnitEnum => $value->name,
            is_array($value), $value instanceof JsonSerializable => (string) json_encode($value, JSON_THROW_ON_ERROR),
            $value instanceof Stringable => (string) $value,
            is_string($value) && $this->looksLikeDate($value) => (string) Date::parse($value)->getTimestamp(),
            is_scalar($value) => (string) $value,
            default => throw new LogicException(sprintf('trusted-devices.fingerprint: the column "%s" holds a %s, which a fingerprint cannot read. Cast it to a string, a date, an enum or an array, or take it out of the list.', $column, get_debug_type($value))),
        };
    }

    private function looksLikeDate(string $value): bool
    {
        return preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/', $value) === 1;
    }
}
