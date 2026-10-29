<?php

declare(strict_types=1);

use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Schema;
use Laravel\Fortify\Fortify;
use Olgun\TrustedDevices\Support\Fingerprint;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Workbench\App\Enums\Level;
use Workbench\App\Enums\Plain;

/**
 * The fingerprint reads what a column really holds (F4, M30), and the check
 * command names the settings that break or weaken a trust (F9, M29).
 */
it('gives one fingerprint for a date as a Carbon and as the database string (M30)', function (): void {
    $admin = Machines::admin();
    $admin->forceFill(['two_factor_confirmed_at' => now()->startOfSecond()]);
    $before = resolve(Fingerprint::class)->of($admin);

    $admin->save();
    $admin->refresh();

    expect(is_string($admin->getAttributes()['two_factor_confirmed_at']))->toBeTrue()
        ->and(resolve(Fingerprint::class)->of($admin))->toBe($before);
});

it('ends a trust when an enum or an array column changes, and refuses a type it cannot read (F4)', function (): void {
    Schema::table('users', static function ($table): void {
        $table->string('level')->nullable();
        $table->text('scopes')->nullable();
    });
    config()->set('trusted-devices.fingerprint', ['password', 'level', 'scopes']);
    $fingerprint = resolve(Fingerprint::class);

    $admin = Machines::admin();
    $admin->mergeCasts(['level' => Level::class, 'scopes' => 'array']);
    $admin->forceFill(['level' => Level::Admin, 'scopes' => ['a']]);
    $first = $fingerprint->of($admin);

    $admin->forceFill(['level' => Level::Member]);
    $second = $fingerprint->of($admin);

    $admin->forceFill(['scopes' => ['a', 'b']]);
    $third = $fingerprint->of($admin);

    expect($second)->not->toBe($first)->and($third)->not->toBe($second);

    // A column whose value is an object the fingerprint cannot read.
    $odd = new class extends User
    {
        protected $table = 'users';

        public function getLevelAttribute(): object
        {
            return new stdClass;
        }
    };
    $odd->forceFill(['password' => 'x']);

    expect(fn (): string => $fingerprint->of($odd))->toThrow(LogicException::class, 'the column "level"');
});

it('encodes its parts as a list, so moved separators never collide; reads a pure enum and a Stringable (F4)', function (): void {
    config()->set('trusted-devices.fingerprint', ['first', 'second']);
    $fingerprint = resolve(Fingerprint::class);
    $admin = Machines::admin();

    $admin->setRawAttributes([...$admin->getAttributes(), 'first' => 'a|b', 'second' => 'c']);
    $one = $fingerprint->of($admin);
    $admin->setRawAttributes([...$admin->getAttributes(), 'first' => 'a', 'second' => 'b|c']);

    expect($fingerprint->of($admin))->not->toBe($one);

    $odd = new class extends User
    {
        public mixed $first = null;

        public function getFirstAttribute(): mixed
        {
            return $this->first;
        }
    };
    config()->set('trusted-devices.fingerprint', ['first']);

    $odd->first = Plain::One;
    $enumOne = $fingerprint->of($odd);
    $odd->first = Plain::Two;
    $enumTwo = $fingerprint->of($odd);
    $odd->first = str('one');
    $textOne = $fingerprint->of($odd);
    $odd->first = str('two');

    expect($enumTwo)->not->toBe($enumOne)->and($fingerprint->of($odd))->not->toBe($textOne);
});

it('names a cookie that the app leaves unencrypted (M29)', function (): void {
    $property = new ReflectionProperty(EncryptCookies::class, 'neverEncrypt');
    $before = $property->getValue();

    try {
        EncryptCookies::except(['trusted_device']);

        $this->artisan('trusted-devices:check')->expectsOutputToContain('exception list')->assertFailed();
    } finally {
        $property->setValue(null, $before);
    }
});

it('fails when the guard cannot sign in, or is not Fortify\'s guard (F9)', function (string $case, string $words): void {
    match ($case) {
        'not a session guard' => [config()->set('auth.guards.api', ['driver' => 'token', 'provider' => 'users']), config()->set('trusted-devices.guard', 'api'), config()->set('fortify.guard', 'api')],
        'not fortify\'s' => [config()->set('auth.guards.admins', ['driver' => 'session', 'provider' => 'users']), config()->set('trusted-devices.guard', 'admins')],
    };

    $this->artisan('trusted-devices:check')->expectsOutputToContain($words)->assertFailed();
})->with([
    ['not a session guard', 'is not a session guard'],
    ['not fortify\'s', 'make them the same'],
]);

it('warns about settings that weaken a trust, and still passes (F9)', function (): void {
    config()->set('trusted-devices.fingerprint', ['two_factor_secret']);
    config()->set('fortify.pipelines.login', []);

    try {
        Fortify::authenticateUsing(static fn () => null);

        $this->artisan('trusted-devices:check')
            ->expectsOutputToContain('no "password"')
            ->expectsOutputToContain('pipeline is your own')
            ->expectsOutputToContain('automatic sign-in is refused')
            ->assertSuccessful();
    } finally {
        Fortify::$authenticateUsingCallback = null;
    }
});
