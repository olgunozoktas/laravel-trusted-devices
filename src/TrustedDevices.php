<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laravel\Fortify\Fortify;
use Olgun\TrustedDevices\Events\TrustedDeviceCreated;
use Olgun\TrustedDevices\Events\TrustedDeviceForgotten;
use Olgun\TrustedDevices\Events\TrustedDeviceUsed;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Cookie;
use Olgun\TrustedDevices\Support\DeviceName;
use Olgun\TrustedDevices\Support\Eligibility;
use Olgun\TrustedDevices\Support\Fingerprint;
use Olgun\TrustedDevices\Support\Offer;
use Olgun\TrustedDevices\Support\Settings;

/**
 * Make and check a trusted device. The one place that decides.
 *
 * Until its days end, a trusted device skips the second-factor code and (with
 * `auto_sign_in`) signs its person in by itself. Log out stops the automatic
 * sign-in on that device until the next password sign-in.
 *
 * ## Why each rule is here
 *
 * - A trust is made only with a fresh, one-time offer ({@see Offer}): a stolen
 *   session cookie cannot trust a device for itself.
 * - The cookie carries a 64-character random secret; the table keeps only its
 *   SHA-256, compared with `hash_equals`. A copy of the table signs nobody in.
 * - The end date is the server's. The cookie's own expiry is only a courtesy.
 * - Every use asks {@see Eligibility} again and compares the {@see Fingerprint}:
 *   a new password, a new factor or a lost ability ends the trust, and a trust
 *   of this person that no longer fits is forgotten for good, so it cannot come
 *   back when the ability returns.
 * - Each act fires an event; the secret is in none of them.
 *
 * What it does NOT decide: your own step-up screens and password
 * confirmations. Call {@see self::trustsFor()} there, and keep asking for the
 * password on your most powerful pages (README, "Admin panels").
 */
final readonly class TrustedDevices
{
    public function __construct(
        private Offer $offer,
        private Cookie $cookie,
        private Fingerprint $fingerprint,
        private Eligibility $eligibility,
    ) {}

    public function offeredTo(?Authenticatable $user): bool
    {
        return $user instanceof Authenticatable && $this->eligibility->allows($user);
    }

    /**
     * After an accepted second-factor code: should the question come next? If
     * so, the offer is written, and the caller sends the person to it.
     */
    public function offerAfterCode(Request $request, Authenticatable $user): bool
    {
        if (! $this->offeredTo($user) || $this->offer->isDeclinedBy($user) || $this->trustsFor($request, $user)) {
            return false;
        }

        $this->offer->put($user);

        return true;
    }

    /**
     * Trust the device of this request for `$days` days. Null when there is no
     * fresh offer for this person (no code in this session, too late, or spent).
     */
    public function trust(Request $request, Authenticatable $user, int $days): ?TrustedDevice
    {
        if (! in_array($days, Settings::days(), true)) {
            throw new InvalidArgumentException(sprintf('%d days is not one of the offered choices.', $days));
        }

        if (! $this->offeredTo($user) || ! $this->offer->claim($user)) {
            return null;
        }

        $previous = $this->current($request);

        if ($previous instanceof TrustedDevice && $previous->user_id === $this->key($user)) {
            $this->end($user, $previous, TrustedDeviceForgotten::REPLACED);
        }

        $secret = Str::random(64);

        $device = TrustedDevice::query()->create([
            'uuid' => (string) Str::uuid(),
            'user_id' => $this->key($user),
            'token_hash' => hash('sha256', $secret),
            'fingerprint' => $this->fingerprint->of($user),
            'name' => DeviceName::describe((string) $request->userAgent()),
            'ip_address' => $request->ip(),
            'expires_at' => Date::now()->addDays($days),
            'last_used_at' => Date::now(),
        ]);

        foreach ($this->activeQuery($user)->latest('id')->get()->values() as $position => $old) {
            if ($position >= Settings::maxPerUser()) {
                $this->end($user, $old, TrustedDeviceForgotten::LIMIT);
            }
        }

        $this->cookie->queue($device->uuid, $secret, $days);

        event(new TrustedDeviceCreated($user, $device, $days, $request->ip()));

        return $device;
    }

    /**
     * Does the device of this request skip the code for this person?
     */
    public function trustsFor(Request $request, Authenticatable $user): bool
    {
        $device = $this->current($request);

        return $device instanceof TrustedDevice && $this->stillTrusts($device, $user);
    }

    /**
     * After a password sign-in on a trusted device: the code was skipped, and
     * the device signs in by itself again (Log out had stopped that).
     */
    public function recognise(Request $request, Authenticatable $user): bool
    {
        $device = $this->current($request);

        if (! $device instanceof TrustedDevice || ! $this->stillTrusts($device, $user)) {
            return false;
        }

        $device->forceFill(['signed_out_at' => null, 'last_used_at' => Date::now()])->save();

        event(new TrustedDeviceUsed($user, $device, TrustedDeviceUsed::CODE_SKIPPED, $request->ip()));

        return true;
    }

    /**
     * The person this device signs in by itself, or null: never with
     * `auto_sign_in` off, never after Log out on this device, and never for an
     * account the trust no longer describes.
     */
    public function signInFrom(Request $request): ?Authenticatable
    {
        if (! Settings::autoSignIn() || $this->authenticateUsingRefuses()) {
            return null;
        }

        $device = $this->current($request);

        if (! $device instanceof TrustedDevice || $device->signed_out_at !== null) {
            return null;
        }

        $user = $this->userOf($device);

        if (! $user instanceof Authenticatable || ! $this->stillTrusts($device, $user)) {
            return null;
        }

        $device->forceFill(['last_used_at' => Date::now()])->save();

        event(new TrustedDeviceUsed($user, $device, TrustedDeviceUsed::AUTO_SIGN_IN, $request->ip()));

        return $user;
    }

    /**
     * A code sign-in on a device that this person already trusts (an app whose
     * own login step asked for the code): the device signs in by itself again,
     * as after a password sign-in that skipped the code. No event: nothing was
     * skipped.
     */
    public function resume(Request $request, Authenticatable $user): void
    {
        $device = $this->current($request);

        if ($device instanceof TrustedDevice && $device->signed_out_at !== null && $this->stillTrusts($device, $user)) {
            $device->forceFill(['signed_out_at' => null, 'last_used_at' => Date::now()])->save();
        }
    }

    /**
     * Log out on a trusted device: it stops signing in by itself there. The
     * code stays skipped until the trust ends or is forgotten.
     */
    public function signOut(Request $request, Authenticatable $user): void
    {
        $device = $this->current($request);

        if ($device instanceof TrustedDevice && $device->user_id === $this->key($user)) {
            $device->forceFill(['signed_out_at' => Date::now()])->save();
        }
    }

    /**
     * The live trust named by this request's cookie, whoever it belongs to:
     * found by its uuid, then the secret compared with `hash_equals`.
     */
    public function current(Request $request): ?TrustedDevice
    {
        $cookie = $this->cookie->read($request);

        if ($cookie === null) {
            return null;
        }

        $device = TrustedDevice::query()
            ->where('uuid', $cookie['uuid'])
            ->where('expires_at', '>', Date::now())
            ->first();

        if (! $device instanceof TrustedDevice || ! hash_equals($device->token_hash, hash('sha256', $cookie['secret']))) {
            return null;
        }

        return $device;
    }

    /**
     * Is this trust, today, a trust for this person? Read-only.
     */
    public function belongsTo(TrustedDevice $device, Authenticatable $user): bool
    {
        return $device->user_id === $this->key($user)
            && $this->offeredTo($user)
            && hash_equals($device->fingerprint, $this->fingerprint->of($user));
    }

    /**
     * The live trusts of this person.
     *
     * @return Builder<TrustedDevice>
     */
    public function activeQuery(Authenticatable $user): Builder
    {
        return TrustedDevice::query()
            ->where('user_id', $this->key($user))
            ->where('expires_at', '>', Date::now());
    }

    /**
     * End one trust (a soft delete) and say why.
     */
    public function end(Authenticatable $user, TrustedDevice $device, string $reason): void
    {
        $device->delete();

        event(new TrustedDeviceForgotten($user, $device, $reason));
    }

    /**
     * {@see self::belongsTo()}, and a trust of THIS person that no longer fits
     * them is forgotten for good: an ability given back must not revive it.
     */
    private function stillTrusts(TrustedDevice $device, Authenticatable $user): bool
    {
        if ($this->belongsTo($device, $user)) {
            return true;
        }

        // Switched off (or no days offered): no trust works, and none is ended
        // for it; they work again when it is on.
        if (! Settings::active()) {
            return false;
        }

        if ($device->user_id === $this->key($user)) {
            $this->end($user, $device, TrustedDeviceForgotten::NO_LONGER_FITS);
            $this->cookie->forget();
        }

        return false;
    }

    /**
     * Fortify::authenticateUsing() can refuse a person (a ban) and the
     * automatic sign-in cannot ask it, so while it is set the automatic sign-in
     * is refused, unless the app says every refusal is also in the ability.
     */
    private function authenticateUsingRefuses(): bool
    {
        return class_exists(Fortify::class)
            && Fortify::$authenticateUsingCallback !== null
            && ! Settings::autoSignInWithAuthenticateUsing();
    }

    private function userOf(TrustedDevice $device): ?Authenticatable
    {
        $provider = config('auth.guards.'.Settings::guard().'.provider');

        return is_string($provider) ? Auth::createUserProvider($provider)?->retrieveById($device->user_id) : null;
    }

    private function key(Authenticatable $user): string
    {
        $identifier = $user->getAuthIdentifier();

        return is_scalar($identifier) ? (string) $identifier : '';
    }
}
