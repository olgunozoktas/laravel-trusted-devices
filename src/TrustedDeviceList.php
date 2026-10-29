<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Date;
use Olgun\TrustedDevices\Events\TrustedDeviceForgotten;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Cookie;

/**
 * Seeing and ending a person's own trusts: what a settings page needs.
 *
 * Every method is scoped to the person passed in, so another account's uuid
 * reaches nothing. The list never carries the hash, the fingerprint, the
 * address or an integer id.
 */
final readonly class TrustedDeviceList
{
    public function __construct(
        private TrustedDevices $trustedDevices,
        private Cookie $cookie,
    ) {}

    /**
     * The live trusts, newest first. A trust that a new password or factor
     * ended is not listed, so it cannot read "signs in by itself".
     *
     * @return list<array{uuid: string, device: string, is_current: bool, signs_in: bool, until: string, until_at: string, last_used: string|null}>
     */
    public function for(Request $request, Authenticatable $user): array
    {
        $current = $this->trustedDevices->current($request);

        return array_values($this->trustedDevices->activeQuery($user)->latest('id')->get()
            ->filter(fn (TrustedDevice $device): bool => $this->trustedDevices->belongsTo($device, $user))
            ->map(fn (TrustedDevice $device): array => [
                'uuid' => $device->uuid,
                'device' => $device->name,
                'is_current' => $current instanceof TrustedDevice && $device->is($current),
                'signs_in' => $device->signed_out_at === null,
                'until' => $device->expires_at->toFormattedDayDateString(),
                'until_at' => $device->expires_at->toIso8601String(),
                'last_used' => $device->last_used_at?->diffForHumans(),
            ])->all());
    }

    public function forget(Request $request, Authenticatable $user, string $uuid): bool
    {
        $device = $this->trustedDevices->activeQuery($user)->where('uuid', $uuid)->first();

        if (! $device instanceof TrustedDevice) {
            return false;
        }

        $this->trustedDevices->end($user, $device, TrustedDeviceForgotten::FORGOTTEN);

        if (($this->cookie->read($request)['uuid'] ?? null) === $uuid) {
            $this->cookie->forget();
        }

        return true;
    }

    /**
     * Every trust but the one of this request: call it from your "end all other
     * sessions", or a trusted device signs in again by itself a moment later.
     */
    public function forgetOthers(Request $request, Authenticatable $user): int
    {
        $current = $this->trustedDevices->current($request);
        $forgotten = 0;

        foreach ($this->trustedDevices->activeQuery($user)->get() as $device) {
            if (! $current instanceof TrustedDevice || ! $device->is($current)) {
                $this->trustedDevices->end($user, $device, TrustedDeviceForgotten::OTHERS);
                $forgotten++;
            }
        }

        return $forgotten;
    }

    /**
     * Every trust of this person: call it when they lose what a trust needs (a
     * role taken away), so an unused device cannot come back when it returns.
     */
    public function forgetAll(Authenticatable $user, string $reason = TrustedDeviceForgotten::NO_LONGER_FITS): int
    {
        $forgotten = 0;

        foreach ($this->trustedDevices->activeQuery($user)->get() as $device) {
            $this->trustedDevices->end($user, $device, $reason);
            $forgotten++;
        }

        return $forgotten;
    }

    /**
     * After you end ONE other session: a session row does not say which device
     * made it, so every other trust stops signing in by itself and asks for the
     * password at its next sign-in (not for the code).
     */
    public function stopOthersSigningIn(Request $request, Authenticatable $user): int
    {
        $current = $this->trustedDevices->current($request);
        $stopped = 0;

        foreach ($this->trustedDevices->activeQuery($user)->whereNull('signed_out_at')->get() as $device) {
            if (! $current instanceof TrustedDevice || ! $device->is($current)) {
                $device->forceFill(['signed_out_at' => Date::now()])->save();
                $stopped++;
            }
        }

        return $stopped;
    }
}
