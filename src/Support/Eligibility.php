<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;

/**
 * May this person trust a device, and may a trust still serve them?
 *
 * All three, checked on every use, never only when the trust is made:
 *
 * 1. The package is on and offers at least one number of days.
 * 2. The person has a CONFIRMED second factor: there is no code to skip
 *    otherwise. Fortify's `hasEnabledTwoFactorAuthentication()` when the model
 *    has it; else a secret and a confirmation time.
 * 3. They pass `trusted-devices.ability`, when one is set (a Gate ability).
 *
 * Bind your own subclass in the container to change the rule.
 */
class Eligibility
{
    public function allows(Authenticatable $user): bool
    {
        if (! Settings::enabled() || Settings::days() === []) {
            return false;
        }

        if (! $this->hasConfirmedFactor($user)) {
            return false;
        }

        $ability = Settings::ability();

        return $ability === null || Gate::forUser($user)->allows($ability);
    }

    protected function hasConfirmedFactor(Authenticatable $user): bool
    {
        if (method_exists($user, 'hasEnabledTwoFactorAuthentication')) {
            return (bool) $user->hasEnabledTwoFactorAuthentication();
        }

        if (! $user instanceof Model) {
            return false;
        }

        $secret = $user->getAttribute('two_factor_secret');
        $confirmed = $user->getAttribute('two_factor_confirmed_at');

        return is_string($secret) && $secret !== ''
            && ($confirmed instanceof DateTimeInterface || (is_string($confirmed) && $confirmed !== ''));
    }
}
