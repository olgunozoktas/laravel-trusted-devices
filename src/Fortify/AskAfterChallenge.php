<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Fortify;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Laravel\Fortify\Contracts\TwoFactorLoginResponse;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDevices;
use Symfony\Component\HttpFoundation\Response;

/**
 * After an accepted code at Fortify's challenge, ask "Keep me signed in on
 * this machine?" — and otherwise answer exactly as the response it decorates.
 *
 * It DECORATES whatever your app bound to `TwoFactorLoginResponse` (the service
 * provider uses the container's `extend()`), so your own response keeps
 * working. A JSON request is never redirected to the question.
 */
final readonly class AskAfterChallenge implements TwoFactorLoginResponse
{
    public function __construct(
        private TwoFactorLoginResponse $inner,
        private TrustedDevices $trustedDevices,
    ) {}

    /**
     * @param  Request  $request
     */
    public function toResponse($request): Response
    {
        $user = $request->user(Settings::guard());

        if (! $request->wantsJson()
            && Settings::fortifyAsksAfterChallenge()
            && $user instanceof Authenticatable
            && $this->trustedDevices->offerAfterCode($request, $user)) {
            return redirect()->route('trusted-devices.create');
        }

        return $this->inner->toResponse($request);
    }
}
