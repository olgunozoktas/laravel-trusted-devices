<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;
use Olgun\TrustedDevices\Models\TrustedDevice;

/**
 * A trusted device did what a trust allows: it signed its person in by itself
 * (`AUTO_SIGN_IN`), or a password sign-in on it skipped the code
 * (`CODE_SKIPPED`). Listen to it for your audit log.
 */
final class TrustedDeviceUsed
{
    use SerializesModels;

    public const string AUTO_SIGN_IN = 'auto_sign_in';

    public const string CODE_SKIPPED = 'code_skipped';

    public function __construct(
        public Authenticatable $user,
        public TrustedDevice $device,
        public string $how,
        public ?string $ipAddress,
    ) {}
}
