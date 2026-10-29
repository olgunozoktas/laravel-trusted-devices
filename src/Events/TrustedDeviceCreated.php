<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Queue\SerializesModels;
use Olgun\TrustedDevices\Models\TrustedDevice;

/**
 * A person trusted a device. Listen to it to write your audit line and to send
 * the "Was this you?" mail: a new trust is the moment the account owner should
 * hear about. It never carries the secret; a queued listener gets the models by
 * their keys (`SerializesModels`), never their attributes.
 */
final class TrustedDeviceCreated
{
    use SerializesModels;

    public function __construct(
        public Authenticatable $user,
        public TrustedDevice $device,
        public int $days,
        public ?string $ipAddress,
    ) {}
}
