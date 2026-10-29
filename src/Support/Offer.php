<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;

/**
 * The one-time right to answer "Keep me signed in on this machine?".
 *
 * Written into the session when a second-factor code is accepted, it lives
 * `trusted-devices.offer_seconds` (120 by default) and the answer spends it.
 * This is what stops somebody holding a STOLEN SESSION COOKIE from posting
 * "trust for 30 days": the post is refused unless this session proved a code
 * moments ago.
 *
 * Spent once, atomically: the session is not locked, so two posts at the same
 * moment would both read the offer as fresh. Each offer carries a random nonce,
 * and `claim()` spends it with `Cache::add()`, which only one caller can win.
 * It names the person, so another account's offer in the same session is not
 * theirs.
 */
final readonly class Offer
{
    private const string OFFER = 'trusted_devices.offer';

    private const string DECLINED = 'trusted_devices.declined_for';

    public function __construct(private Session $session) {}

    public function put(Authenticatable $user): void
    {
        $this->session->put(self::OFFER, ['user' => $this->key($user), 'at' => Date::now()->getTimestamp(), 'nonce' => Str::random(40)]);
    }

    public function isFreshFor(Authenticatable $user): bool
    {
        $offer = $this->session->get(self::OFFER);

        if (! is_array($offer) || ($offer['user'] ?? null) !== $this->key($user)) {
            return false;
        }

        $at = $offer['at'] ?? null;

        return is_int($at) && Date::now()->getTimestamp() - $at <= Settings::offerSeconds();
    }

    /**
     * Spend a fresh offer for this person, once: true for exactly one caller.
     */
    public function claim(Authenticatable $user): bool
    {
        if (! $this->isFreshFor($user)) {
            return false;
        }

        $offer = $this->session->get(self::OFFER);
        $nonce = is_array($offer) ? ($offer['nonce'] ?? null) : null;

        $this->session->forget(self::OFFER);

        return is_string($nonce)
            && $nonce !== ''
            && Cache::add('trusted-devices-offer:'.hash('sha256', $nonce), true, Settings::offerSeconds());
    }

    /**
     * "No, ask every time": spend the offer and do not ask again in this
     * session.
     */
    public function decline(Authenticatable $user): void
    {
        $this->session->forget(self::OFFER);
        $this->session->put(self::DECLINED, $this->key($user));
    }

    public function isDeclinedBy(Authenticatable $user): bool
    {
        return $this->session->get(self::DECLINED) === $this->key($user);
    }

    private function key(Authenticatable $user): string
    {
        $identifier = $user->getAuthIdentifier();

        return is_scalar($identifier) ? (string) $identifier : '';
    }
}
