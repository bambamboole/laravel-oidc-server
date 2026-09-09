<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\AuthenticateIdentity;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\AuthenticatedSessionController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\ConfirmablePasswordController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\EmailVerificationPromptController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\NewPasswordController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\PasskeyAuthenticatedSessionController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\PasswordResetLinkController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\RegisteredUserController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\SendEmailVerificationNotificationController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\ShowConfirmedPasswordStatusController;
use Bambamboole\LaravelOidc\Server\Authentication\Controllers\VerifyEmailController;
use Bambamboole\LaravelOidc\Server\Brokering\Controllers\LinkedAccountController;
use Bambamboole\LaravelOidc\Server\Brokering\Controllers\SocialAuthenticationController;
use Bambamboole\LaravelOidc\Server\Credential\Controllers\FactorEnrollmentController;
use Bambamboole\LaravelOidc\Server\Credential\Controllers\TwoFactorChallengeController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\AccessTokenController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\ApproveAuthorizationController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\AuthorizationServerMetadataController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\ClientRegistrationController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\DenyAuthorizationController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\DiscoveryController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\EndSessionController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\IntrospectionController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\ProtectedResourceController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\RevocationController;
use Bambamboole\LaravelOidc\Server\Http\Controllers\UserinfoController;
use Bambamboole\LaravelOidc\Server\Keys\JwksController;
use Bambamboole\LaravelOidc\Server\Realm\RealmPath;
use Bambamboole\LaravelOidc\Server\Realm\ResolveRealm;
use Illuminate\Auth\Middleware\RequirePassword;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Laravel\Passkeys\Http\Controllers\PasskeyConfirmationController;
use Laravel\Passkeys\Http\Controllers\PasskeyLoginController;

$guard = (string) config('oidc.auth.guard', 'identity');
$guest = 'guest:'.$guard;
$authenticated = AuthenticateIdentity::class.':'.$guard;
$passwordConfirmed = RequirePassword::using('identity.password.confirm');

/** @var array<int, string> $shared */
$shared = (array) config('oidc.routes.middleware', []);

Route::middleware([ResolveRealm::class, ...$shared])
    ->prefix(RealmPath::SEGMENT.'/{realm}')
    ->where(['realm' => '[A-Za-z0-9._-]+'])
    ->group(function () use ($guest, $authenticated, $passwordConfirmed): void {
        Route::middleware('web')->group(function () use ($guest, $authenticated, $passwordConfirmed): void {
            Route::middleware($guest)->group(function (): void {
                Route::get('auth/login', [AuthenticatedSessionController::class, 'create'])->name('identity.login');
                Route::get('auth/register', [RegisteredUserController::class, 'create'])->name('identity.register');
                Route::get('auth/forgot-password', [PasswordResetLinkController::class, 'create'])->name('identity.password.request');
                Route::get('auth/reset-password/{token}', [NewPasswordController::class, 'create'])->name('identity.password.reset');
                Route::get('auth/two-factor-challenge', [TwoFactorChallengeController::class, 'create'])->name('identity.two-factor.login');
                Route::get('auth/two-factor-challenge/factor/{provider}/{enrollment?}', [TwoFactorChallengeController::class, 'selectFactor'])->name('identity.two-factor.login.factor');
                Route::get('auth/social/{provider}', [SocialAuthenticationController::class, 'redirect'])->name('identity.social.redirect');

                Route::middleware('throttle:5,1')->group(function (): void {
                    Route::post('auth/login', [AuthenticatedSessionController::class, 'store'])->name('identity.login.store');
                    Route::post('auth/register', [RegisteredUserController::class, 'store'])->name('identity.register.store');
                    Route::post('auth/forgot-password', [PasswordResetLinkController::class, 'store'])->name('identity.password.email');
                    Route::post('auth/reset-password', [NewPasswordController::class, 'store'])->name('identity.password.update');
                    Route::post('auth/two-factor-challenge', [TwoFactorChallengeController::class, 'store'])->name('identity.two-factor.login.store');
                    Route::get('auth/two-factor-challenge/options', [TwoFactorChallengeController::class, 'options'])->name('identity.two-factor.login.options');
                    Route::get('auth/passkeys/login/options', [PasskeyLoginController::class, 'index'])->name('identity.passkey.login-options');
                    Route::post('auth/passkeys/login', [PasskeyAuthenticatedSessionController::class, 'store'])->name('identity.passkey.login');
                });
            });

            Route::middleware($authenticated)->group(function () use ($passwordConfirmed): void {
                Route::get('auth/user/confirm-password', [ConfirmablePasswordController::class, 'show'])->name('identity.password.confirm');
                Route::post('auth/user/confirm-password', [ConfirmablePasswordController::class, 'store'])->middleware('throttle:5,1')->name('identity.password.confirm.store');
                Route::get('auth/user/confirmed-password-status', ShowConfirmedPasswordStatusController::class)->name('identity.password.confirmation');

                Route::get('auth/email/verify', EmailVerificationPromptController::class)->name('identity.verification.notice');
                Route::get('auth/email/verify/{id}/{hash}', VerifyEmailController::class)->middleware(['signed', 'throttle:6,1'])->name('identity.verification.verify');
                Route::post('auth/email/verification-notification', SendEmailVerificationNotificationController::class)->middleware('throttle:6,1')->name('identity.verification.send');

                Route::get('auth/passkeys/confirm/options', [PasskeyConfirmationController::class, 'index'])->middleware('throttle:5,1')->name('identity.passkey.confirm-options');
                Route::post('auth/passkeys/confirm', [PasskeyConfirmationController::class, 'store'])->middleware('throttle:5,1')->name('identity.passkey.confirm');

                Route::middleware($passwordConfirmed)->group(function (): void {
                    Route::get('auth/user/two-factor/factors', [FactorEnrollmentController::class, 'index'])->name('identity.two-factor.factors');
                    Route::post('auth/user/two-factor/{provider}', [FactorEnrollmentController::class, 'store'])->middleware('throttle:5,1')->name('identity.two-factor.enroll');
                    Route::post('auth/user/two-factor/{provider}/confirm', [FactorEnrollmentController::class, 'confirm'])->middleware('throttle:5,1')->name('identity.two-factor.enroll.confirm');
                    Route::delete('auth/user/two-factor/{provider}/{enrollment}', [FactorEnrollmentController::class, 'destroy'])->name('identity.two-factor.revoke');

                    Route::get('auth/user/social/{provider}', [LinkedAccountController::class, 'link'])->name('identity.social.link');
                    Route::delete('auth/user/social/{socialAccount}', [LinkedAccountController::class, 'destroy'])->name('identity.social.destroy');
                });
            });

            Route::get('oauth/authorize', [AuthorizationController::class, 'authorize'])->name('oidc.authorize');
            Route::match(['get', 'post'], 'oauth/logout', EndSessionController::class)->name('oidc.logout');

            Route::middleware($authenticated)->group(function (): void {
                Route::post('oauth/authorize', [ApproveAuthorizationController::class, 'approve'])->name('oidc.approve');
                Route::delete('oauth/authorize', [DenyAuthorizationController::class, 'deny'])->name('oidc.deny');
            });
        });

        // The identity provider must keep issuing tokens while a third party's
        // cookie is absent, so these carry no session middleware.
        Route::match(['get', 'post'], 'auth/social/{provider}/callback', [SocialAuthenticationController::class, 'callback'])
            ->middleware([EncryptCookies::class, AddQueuedCookiesToResponse::class, StartSession::class, ShareErrorsFromSession::class])
            ->name('identity.social.callback');

        Route::get('.well-known/jwks.json', JwksController::class)->name('oidc.jwks');
        Route::get('.well-known/openid-configuration', DiscoveryController::class)->name('oidc.discovery');
        Route::match(['get', 'post'], 'oauth/userinfo', UserinfoController::class)->name('oidc.userinfo');

        Route::middleware('throttle')->group(function (): void {
            Route::post('oauth/token', [AccessTokenController::class, 'issueToken'])->name('oidc.token');
            Route::post('oauth/introspect', IntrospectionController::class)->name('oidc.introspect');
            Route::post('oauth/revoke', RevocationController::class)->name('oidc.revoke');

            if (config('oidc.dcr.enabled', false)) {
                Route::post('oauth/register', ClientRegistrationController::class)->name('oidc.register');
            }
        });
    });

/**
 * RFC 8414 §3.1 and RFC 9728 §3.1 insert the well-known segment ahead of the
 * issuer's path rather than appending it, so these two sit outside the realm
 * prefix and carry the realm behind it.
 */
Route::middleware([ResolveRealm::class, ...$shared])
    ->where(['realm' => '[A-Za-z0-9._-]+'])
    ->group(function (): void {
        Route::get('.well-known/oauth-authorization-server/'.RealmPath::SEGMENT.'/{realm}/{path?}', AuthorizationServerMetadataController::class)
            ->where('path', '.*')
            ->name('oidc.authorization-server');
        Route::get('.well-known/oauth-protected-resource/'.RealmPath::SEGMENT.'/{realm}/{path?}', ProtectedResourceController::class)
            ->where('path', '.*')
            ->name('oidc.protected-resource');
    });
