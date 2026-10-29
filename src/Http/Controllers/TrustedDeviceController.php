<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Offer;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDeviceList;
use Olgun\TrustedDevices\TrustedDevices;

/**
 * The question after a code, its answer, and Forget. Every rule about WHEN a
 * device may be trusted is in {@see TrustedDevices}; this only reads answers.
 *
 * No password confirmation on these routes: the question comes seconds after a
 * code and a password, and Forget only REDUCES access.
 */
final class TrustedDeviceController extends Controller
{
    public function __construct(
        private readonly TrustedDevices $trustedDevices,
        private readonly TrustedDeviceList $trustedDeviceList,
        private readonly Offer $offer,
    ) {}

    public function create(Request $request): View|RedirectResponse
    {
        $user = $this->user();

        if (! $this->trustedDevices->offeredTo($user) || ! $this->offer->isFreshFor($user)) {
            return redirect()->intended(Settings::home());
        }

        // `first()`: your view from `trusted-devices.views.question`, and the
        // package's own page when that view does not exist.
        return app(ViewFactory::class)->first([Settings::questionView(), 'trusted-devices::question'], [
            'choices' => Settings::days(),
            'action' => route('trusted-devices.store'),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $user = $this->user();

        abort_unless($this->trustedDevices->offeredTo($user), 403);

        $request->validate([
            'days' => ['required', 'string', Rule::in([...array_map(strval(...), Settings::days()), 'never'])],
        ]);

        $days = $request->string('days')->value();

        if ($days === 'never') {
            $this->offer->decline($user);

            return redirect()->intended(Settings::home());
        }

        $device = $this->trustedDevices->trust($request, $user, (int) $days);

        if (! $device instanceof TrustedDevice) {
            return redirect()->intended(Settings::home())
                ->with('trusted-devices.status', 'too-late');
        }

        return redirect()->intended(Settings::home())
            ->with('trusted-devices.status', 'trusted');
    }

    public function destroy(Request $request, string $uuid): RedirectResponse
    {
        $user = $this->user();

        abort_unless(Str::isUuid($uuid), 404);

        return back()->with('trusted-devices.status', $this->trustedDeviceList->forget($request, $user, $uuid) ? 'forgotten' : 'already-forgotten');
    }

    private function user(): Authenticatable
    {
        $user = Auth::guard(Settings::guard())->user();

        abort_unless($user instanceof Authenticatable, 403);

        return $user;
    }
}
