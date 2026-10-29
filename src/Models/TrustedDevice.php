<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Olgun\TrustedDevices\Support\Settings;
use Override;

/**
 * One device a person chose to trust. Written by `TrustedDevices` and
 * `TrustedDeviceList` only; the migration says what each column is for.
 *
 * @property int $id
 * @property string $uuid
 * @property string $user_id
 * @property string $token_hash
 * @property string $fingerprint
 * @property string $name
 * @property string|null $ip_address
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $last_used_at
 * @property CarbonImmutable|null $signed_out_at
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 * @property CarbonImmutable|null $deleted_at
 */
final class TrustedDevice extends Model
{
    use SoftDeletes;

    protected $fillable = ['uuid', 'user_id', 'token_hash', 'fingerprint', 'name', 'ip_address', 'expires_at', 'last_used_at', 'signed_out_at'];

    /**
     * The hash and the fingerprint never leave the server, also not in a
     * serialised model.
     *
     * @var list<string>
     */
    protected $hidden = ['token_hash', 'fingerprint'];

    #[Override]
    public function getTable(): string
    {
        return Settings::table();
    }

    #[Override]
    public function getConnectionName(): ?string
    {
        return Settings::connection() ?? parent::getConnectionName();
    }

    /**
     * @return array<string, string>
     */
    #[Override]
    protected function casts(): array
    {
        return [
            'user_id' => 'string',
            'expires_at' => 'immutable_datetime',
            'last_used_at' => 'immutable_datetime',
            'signed_out_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
            'deleted_at' => 'immutable_datetime',
        ];
    }
}
