<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Cookie;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDevices;
use Symfony\Component\HttpFoundation\Response;

/**
 * A guest whose browser carries a live trusted-device cookie is signed in
 * before anything else asks who they are.
 *
 * The service provider appends it to the `web` group and puts it before
 * `AuthenticatesRequests` in the middleware priority, so it runs after the
 * session has started and before `auth` would send the guest to the sign-in
 * page. It signs in WITHOUT Laravel's remember cookie (the trust is the
 * device's memory) and with a new session id, as every sign-in does. The
 * `Login` event fires, so the sign-in reaches your audit log like any other.
 *
 * A cookie that names nothing live is dropped from the browser.
 */
final readonly class SignInFromTrustedDevice
{
    public function __construct(
        private TrustedDevices $trustedDevices,
        private Cookie $cookie,
    ) {}

    /**
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! Settings::enabled() || ! Settings::autoSignIn() || ! $this->cookie->has($request)) {
            return $next($request);
        }

        $guard = Auth::guard(Settings::guard());

        if ($guard->check()) {
            return $next($request);
        }

        if (! $this->trustedDevices->current($request) instanceof TrustedDevice) {
            $this->cookie->forget();

            return $next($request);
        }

        $user = $this->trustedDevices->signInFrom($request);

        if ($user instanceof Authenticatable) {
            $guard->login($user);
            $request->session()->regenerate();
        }

        return $next($request);
    }
}
