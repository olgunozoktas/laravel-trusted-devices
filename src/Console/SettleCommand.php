<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Date;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDeviceList;
use Olgun\TrustedDevices\TrustedDevices;

/**
 * Forget every trust of each person who may no longer hold one (the ability,
 * the factor or the password changed). A trust that no longer fits is already
 * refused and forgotten at its next USE; this reaches the devices that are not
 * used, such as a lost laptop. Schedule it (hourly is plenty), or call
 * `TrustedDeviceList::forgetAll()` where your app takes a role away.
 */
final class SettleCommand extends Command
{
    protected $signature = 'trusted-devices:settle';

    protected $description = 'Forget the trusts of people who may no longer hold one';

    public function handle(TrustedDevices $trustedDevices, TrustedDeviceList $list): int
    {
        if (! Settings::active()) {
            $this->components->info('Switched off (or no days offered): no trust is ended while off.');

            return self::SUCCESS;
        }

        $name = config('auth.guards.'.Settings::guard().'.provider');
        $provider = is_string($name) ? Auth::createUserProvider($name) : null;
        $forgotten = 0;

        $holders = TrustedDevice::query()->where('expires_at', '>', Date::now())->get(['user_id'])->pluck('user_id')->unique();

        foreach ($holders as $id) {
            $user = $provider?->retrieveById($id);

            if ($user instanceof Authenticatable && ! $trustedDevices->offeredTo($user)) {
                $forgotten += $list->forgetAll($user);
            }
        }

        $this->components->info(sprintf('Forgot %d trust(s).', $forgotten));

        return self::SUCCESS;
    }
}
