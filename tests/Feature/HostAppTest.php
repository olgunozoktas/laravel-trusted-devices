<?php

declare(strict_types=1);

use Illuminate\Http\JsonResponse;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\Contracts\RedirectsIfTwoFactorAuthenticatable;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider;
use Laravel\Fortify\Contracts\TwoFactorLoginResponse;
use Laravel\Fortify\LoginRateLimiter;
use Olgun\TrustedDevices\Fortify\AskAfterChallenge;
use Olgun\TrustedDevices\Fortify\SkipChallengeOnTrustedDevice;
use Olgun\TrustedDevices\Tests\Support\Machines;
use Symfony\Component\HttpFoundation\Response;

/**
 * The package lives beside the host app's own choices: it DECORATES the app's
 * two-factor login response, and it replaces Fortify's challenge step only
 * while that step is still Fortify's own class.
 */
beforeEach(function (): void {
    config()->set('trusted-devices.ability', 'admin');
});

it('decorates the response that Fortify ships', function (): void {
    expect(resolve(TwoFactorLoginResponse::class))->toBeInstanceOf(AskAfterChallenge::class)
        ->and(resolve(RedirectsIfTwoFactorAuthenticatable::class))->toBeInstanceOf(SkipChallengeOnTrustedDevice::class);
});

it("answers with the app's own response when there is nothing to ask", function (): void {
    app()->singleton(TwoFactorLoginResponse::class, static fn (): TwoFactorLoginResponse => new class implements TwoFactorLoginResponse
    {
        public function toResponse($request): Response
        {
            return new JsonResponse(['the app' => 'answered'], 299);
        }
    });

    $member = Machines::member();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $member->email, 'password' => 'password']);

    $this->post(route('two-factor.login.store'), ['code' => '123456'])->assertStatus(299);
});

it("asks the question in front of the app's own response for a person who may be asked", function (): void {
    app()->singleton(TwoFactorLoginResponse::class, static fn (): TwoFactorLoginResponse => new class implements TwoFactorLoginResponse
    {
        public function toResponse($request): Response
        {
            return new JsonResponse([], 299);
        }
    });

    $admin = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->post(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->post(route('two-factor.login.store'), ['code' => '123456'])->assertRedirect(route('trusted-devices.create'));
});

it("leaves an app's own challenge step in place", function (): void {
    $own = new class(app('auth')->guard(), app(LoginRateLimiter::class)) extends RedirectIfTwoFactorAuthenticatable {};

    app()->scoped(RedirectsIfTwoFactorAuthenticatable::class, static fn () => $own);

    expect(resolve(RedirectsIfTwoFactorAuthenticatable::class))->toBe($own);
});

it('never sends a JSON sign-in to the question', function (): void {
    $admin = Machines::admin();
    $this->mock(TwoFactorAuthenticationProvider::class)->shouldReceive('verify')->andReturn(true);

    $this->postJson(route('login.store'), ['email' => $admin->email, 'password' => 'password']);

    $this->postJson(route('two-factor.login.store'), ['code' => '123456'])->assertNoContent();
});
