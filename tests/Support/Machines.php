<?php

declare(strict_types=1);

namespace Olgun\TrustedDevices\Tests\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Laravel\Fortify\Fortify;
use Olgun\TrustedDevices\Models\TrustedDevice;
use Olgun\TrustedDevices\Support\Offer;
use Olgun\TrustedDevices\Support\Settings;
use Olgun\TrustedDevices\TrustedDevices;
use PHPUnit\Framework\Assert;
use Workbench\App\Models\User;

/**
 * People with a REAL confirmed factor, and a trust made the way the question
 * makes it (an offer, then the answer), returned as the cookie value a browser
 * sends back.
 */
final class Machines
{
    public const string SECRET = 'JBSWY3DPEHPK3PXP';

    public const string AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36';

    private static int $people = 0;

    /** Passes the `admin` ability of the test app. */
    public static function admin(): User
    {
        return self::person('admin');
    }

    /** Fails it. */
    public static function member(): User
    {
        return self::person('example');
    }

    public static function withoutFactor(): User
    {
        return User::query()->create([
            'name' => 'No factor',
            'email' => 'nofactor'.(++self::$people).'@admin.test',
            'password' => 'password',
        ]);
    }

    public static function trust(User $user, int $days = 7): string
    {
        resolve(Offer::class)->put($user);

        $request = Request::create('/trust-this-device', 'POST', server: ['HTTP_USER_AGENT' => self::AGENT, 'REMOTE_ADDR' => '203.0.113.7']);

        Assert::assertInstanceOf(TrustedDevice::class, resolve(TrustedDevices::class)->trust($request, $user, $days));

        $cookie = Cookie::queued(Settings::cookieName());
        Cookie::unqueue(Settings::cookieName());

        Assert::assertNotNull($cookie);

        return (string) $cookie->getValue();
    }

    public static function deviceFor(string $cookie): TrustedDevice
    {
        $device = TrustedDevice::withTrashed()->where('uuid', explode('|', $cookie)[0])->first();

        Assert::assertInstanceOf(TrustedDevice::class, $device);

        return $device;
    }

    private static function person(string $domain): User
    {
        $n = ++self::$people;

        $user = User::query()->create([
            'name' => 'Person '.$n,
            'email' => 'person'.$n.'@'.$domain.'.test',
            'password' => 'password',
        ]);

        $user->forceFill([
            'two_factor_secret' => Fortify::currentEncrypter()->encrypt(self::SECRET),
            'two_factor_recovery_codes' => Fortify::currentEncrypter()->encrypt((string) json_encode(['recovery-one', 'recovery-two'])),
            'two_factor_confirmed_at' => now(),
        ])->save();

        return $user->refresh();
    }
}
