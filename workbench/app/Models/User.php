<?php

declare(strict_types=1);

namespace Workbench\App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Fortify\TwoFactorAuthenticatable;

/**
 * The test app's user: Laravel's users table plus Fortify's two-factor
 * columns, with NO cast on `two_factor_confirmed_at` (a string from the
 * database, a date after `forceFill(now())`), as many real apps have it.
 */
final class User extends Authenticatable
{
    use TwoFactorAuthenticatable;

    protected $guarded = [];

    protected $hidden = ['password', 'two_factor_secret', 'two_factor_recovery_codes'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
