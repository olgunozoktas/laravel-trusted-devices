<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Olgun\TrustedDevices\Models\TrustedDevice;

/**
 * A trust ended before its days: the person forgot it (`FORGOTTEN`), ended the
 * other devices (`OTHERS`), lost what a trust needs (`NO_LONGER_FITS`: the
 * ability, the factor or the password changed), trusted the same browser again
 * (`REPLACED`), or passed the limit of live trusts (`LIMIT`).
 */
final readonly class TrustedDeviceForgotten
{
    public const string FORGOTTEN = 'forgotten';

    public const string OTHERS = 'others';

    public const string NO_LONGER_FITS = 'no_longer_fits';

    public const string REPLACED = 'replaced';

    public const string LIMIT = 'limit';

    public function __construct(
        public Authenticatable $user,
        public TrustedDevice $device,
        public string $reason,
    ) {}
}
