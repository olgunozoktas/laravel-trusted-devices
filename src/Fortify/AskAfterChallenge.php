<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Fortify;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
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
 * working. A JSON request is never redirected to the question; an Inertia
 * request gets a 409 with X-Inertia-Location; with no question route (the
 * package's routes off and none of the app's) the app's response answers.
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

        if (! $user instanceof Authenticatable) {
            return $this->inner->toResponse($request);
        }

        // A code sign-in on a device this person already trusts: it signs in
        // by itself again (an app whose own login step asked for the code).
        $this->trustedDevices->resume($request, $user);

        if ($request->wantsJson()
            || ! Settings::fortifyAsksAfterChallenge()
            || ! Route::has('trusted-devices.create')
            || ! $this->trustedDevices->offerAfterCode($request, $user)) {
            return $this->inner->toResponse($request);
        }

        $question = route('trusted-devices.create');

        // Inertia follows a 409 with X-Inertia-Location as a full page visit,
        // so the Blade question is not drawn inside a modal.
        return $request->headers->has('X-Inertia')
            ? new Response('', 409, ['X-Inertia-Location' => $question])
            : redirect()->to($question);
    }
}
