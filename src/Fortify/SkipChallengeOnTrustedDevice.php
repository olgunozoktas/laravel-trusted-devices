<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Fortify;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\Fortify;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDevices;

/**
 * Fortify's login step that sends a person with a factor to the challenge —
 * except on a device they trust: there the password, checked here as Fortify
 * checks it, is enough, and the sign-in goes on.
 *
 * The service provider binds it to Fortify's `RedirectsIfTwoFactorAuthenticatable`
 * contract ONLY while that contract still resolves to Fortify's own class, so an
 * app's own step is never replaced. The challenge decision below mirrors
 * Fortify 1.x's `RedirectIfTwoFactorAuthenticatable::handle()`; the credentials
 * are validated once, by Fortify's own method.
 */
class SkipChallengeOnTrustedDevice extends RedirectIfTwoFactorAuthenticatable
{
    /**
     * @param  Request  $request
     * @param  callable  $next
     * @return mixed
     */
    public function handle($request, $next)
    {
        $user = $this->validateCredentials($request);
        $trustedDevices = app(TrustedDevices::class);

        if (Settings::fortifySkipsChallenge() && $user instanceof Authenticatable && $trustedDevices->trustsFor($request, $user)) {
            $response = $next($request);
            $trustedDevices->recognise($request, $user);

            return $response;
        }

        $secret = $user instanceof Model ? $user->getAttribute('two_factor_secret') : null;
        $confirmedAt = $user instanceof Model ? $user->getAttribute('two_factor_confirmed_at') : null;
        $usesTrait = is_object($user) && in_array(TwoFactorAuthenticatable::class, class_uses_recursive($user), true);

        if (Fortify::confirmsTwoFactorAuthentication()) {
            return $secret && $confirmedAt !== null && $usesTrait
                ? $this->twoFactorChallengeResponse($request, $user)
                : $next($request);
        }

        return $secret && $usesTrait
            ? $this->twoFactorChallengeResponse($request, $user)
            : $next($request);
    }
}
