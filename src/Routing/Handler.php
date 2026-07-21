<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Routing;

use Bambamboole\LaravelOidc\Auth\Controllers\AuthenticatedSessionController;
use Bambamboole\LaravelOidc\Auth\Controllers\ConfirmablePasswordController;
use Bambamboole\LaravelOidc\Auth\Controllers\ConfirmTwoFactorAuthenticationController;
use Bambamboole\LaravelOidc\Auth\Controllers\DisableTwoFactorAuthenticationController;
use Bambamboole\LaravelOidc\Auth\Controllers\EmailVerificationPromptController;
use Bambamboole\LaravelOidc\Auth\Controllers\EnableTwoFactorAuthenticationController;
use Bambamboole\LaravelOidc\Auth\Controllers\LinkedAccountController;
use Bambamboole\LaravelOidc\Auth\Controllers\NewPasswordController;
use Bambamboole\LaravelOidc\Auth\Controllers\PasswordResetLinkController;
use Bambamboole\LaravelOidc\Auth\Controllers\RegenerateRecoveryCodesController;
use Bambamboole\LaravelOidc\Auth\Controllers\RegisteredUserController;
use Bambamboole\LaravelOidc\Auth\Controllers\SendEmailVerificationNotificationController;
use Bambamboole\LaravelOidc\Auth\Controllers\ShowConfirmedPasswordStatusController;
use Bambamboole\LaravelOidc\Auth\Controllers\ShowRecoveryCodesController;
use Bambamboole\LaravelOidc\Auth\Controllers\ShowTwoFactorQrCodeController;
use Bambamboole\LaravelOidc\Auth\Controllers\ShowTwoFactorSecretKeyController;
use Bambamboole\LaravelOidc\Auth\Controllers\SocialAuthenticationController;
use Bambamboole\LaravelOidc\Auth\Controllers\TwoFactorChallengeController;
use Bambamboole\LaravelOidc\Auth\Controllers\VerifyEmailController;
use Bambamboole\LaravelOidc\Auth\Middleware\AuthenticateIdentity;
use Bambamboole\LaravelOidc\Http\Controllers\ApproveAuthorizationController;
use Bambamboole\LaravelOidc\Http\Controllers\AuthorizationController;
use Bambamboole\LaravelOidc\Http\Controllers\DenyAuthorizationController;
use Bambamboole\LaravelOidc\Http\Controllers\DiscoveryController;
use Bambamboole\LaravelOidc\Http\Controllers\EndSessionController;
use Bambamboole\LaravelOidc\Http\Controllers\IntrospectionController;
use Bambamboole\LaravelOidc\Http\Controllers\JwksController;
use Bambamboole\LaravelOidc\Http\Controllers\RevocationController;
use Bambamboole\LaravelOidc\Http\Controllers\UserinfoController;
use Illuminate\Auth\Middleware\RequirePassword;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Laravel\Passkeys\Http\Controllers\PasskeyConfirmationController;
use Laravel\Passkeys\Http\Controllers\PasskeyLoginController;
use Laravel\Passkeys\Http\Controllers\PasskeyRegistrationController;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Laravel\Passport\Http\Controllers\TransientTokenController;

/**
 * The canonical registry of every HTTP endpoint the package can register.
 *
 * Each case's value is the endpoint's route name and the key into the sparse
 * `oidc.handlers` override config. Route paths, controllers, middleware, and
 * HTTP verbs are intrinsic package defaults.
 *
 * Identity routes are namespaced under `identity.*`; protocol endpoints are
 * namespaced under `oidc.*`. The relying party remains free to own Laravel's
 * conventional `login` and `logout` route names.
 */
enum Handler: string
{
    case Login = 'identity.login';
    case LoginStore = 'identity.login.store';
    case Register = 'identity.register';
    case RegisterStore = 'identity.register.store';
    case PasswordRequest = 'identity.password.request';
    case PasswordEmail = 'identity.password.email';
    case PasswordReset = 'identity.password.reset';
    case PasswordUpdate = 'identity.password.update';
    case PasswordConfirm = 'identity.password.confirm';
    case PasswordConfirmStore = 'identity.password.confirm.store';
    case PasswordConfirmation = 'identity.password.confirmation';
    case VerificationNotice = 'identity.verification.notice';
    case VerificationVerify = 'identity.verification.verify';
    case VerificationSend = 'identity.verification.send';
    case TwoFactorLogin = 'identity.two-factor.login';
    case TwoFactorLoginStore = 'identity.two-factor.login.store';
    case TwoFactorEnable = 'identity.two-factor.enable';
    case TwoFactorConfirm = 'identity.two-factor.confirm';
    case TwoFactorDisable = 'identity.two-factor.disable';
    case TwoFactorQrCode = 'identity.two-factor.qr-code';
    case TwoFactorSecretKey = 'identity.two-factor.secret-key';
    case TwoFactorRecoveryCodes = 'identity.two-factor.recovery-codes';
    case TwoFactorRegenerateRecoveryCodes = 'identity.two-factor.regenerate-recovery-codes';
    case PasskeyLoginOptions = 'identity.passkey.login-options';
    case PasskeyLogin = 'identity.passkey.login';
    case PasskeyConfirmOptions = 'identity.passkey.confirm-options';
    case PasskeyConfirm = 'identity.passkey.confirm';
    case PasskeyRegistrationOptions = 'identity.passkey.registration-options';
    case PasskeyStore = 'identity.passkey.store';
    case PasskeyDestroy = 'identity.passkey.destroy';

    case SocialRedirect = 'identity.social.redirect';
    case SocialCallback = 'identity.social.callback';
    case SocialLink = 'identity.social.link';
    case SocialDestroy = 'identity.social.destroy';

    case Jwks = 'oidc.jwks';
    case Discovery = 'oidc.discovery';
    case Userinfo = 'oidc.userinfo';
    case Logout = 'oidc.logout';
    case Introspect = 'oidc.introspect';
    case Revoke = 'oidc.revoke';
    case Authorize = 'oidc.authorize';
    case IssueToken = 'oidc.token';
    case TokenRefresh = 'oidc.token.refresh';
    case Approve = 'oidc.approve';
    case Deny = 'oidc.deny';

    /**
     * Resolve this handler's package defaults, sparse override, and global
     * route settings, or `false` when it is explicitly disabled.
     */
    public function config(): HandlerConfig|false
    {
        /** @var array<string, array{route?: string, controller?: string|array{0: class-string, 1: string}, middleware?: array<int, string>}|false> $handlers */
        $handlers = config('oidc.handlers', []);
        $override = $handlers[$this->value] ?? null;

        if ($override === false) {
            return false;
        }

        $defaults = $this->defaults();
        $resolved = $override === null
            ? $defaults
            : new HandlerConfig(
                route: $override['route'] ?? $defaults->route,
                controller: $override['controller'] ?? $defaults->controller,
                middleware: $override['middleware'] ?? $defaults->middleware,
            );

        /** @var array<int, string> $globalMiddleware */
        $globalMiddleware = config('oidc.routes.middleware', []);
        $prefix = $this === self::Discovery
            ? ''
            : trim((string) config('oidc.routes.prefix', ''), '/');

        return new HandlerConfig(
            route: $prefix === '' ? $resolved->route : $prefix.'/'.ltrim($resolved->route, '/'),
            controller: $resolved->controller,
            middleware: [...$resolved->middleware, ...$globalMiddleware],
        );
    }

    /**
     * The complete package-owned route defaults for this handler.
     */
    public function defaults(): HandlerConfig
    {
        $guard = (string) config('oidc.auth.guard', 'identity');
        $guest = 'guest:'.$guard;
        $authenticated = AuthenticateIdentity::class.':'.$guard;
        $passwordConfirmed = RequirePassword::using(self::PasswordConfirm->value);

        return match ($this) {
            self::Login => new HandlerConfig(
                route: 'auth/login',
                controller: [AuthenticatedSessionController::class, 'create'],
                middleware: ['web', $guest],
            ),
            self::LoginStore => new HandlerConfig(
                route: 'auth/login',
                controller: [AuthenticatedSessionController::class, 'store'],
                middleware: ['web', $guest, 'throttle:5,1'],
            ),
            self::Register => new HandlerConfig(
                route: 'auth/register',
                controller: [RegisteredUserController::class, 'create'],
                middleware: ['web', $guest],
            ),
            self::RegisterStore => new HandlerConfig(
                route: 'auth/register',
                controller: [RegisteredUserController::class, 'store'],
                middleware: ['web', $guest],
            ),
            self::PasswordRequest => new HandlerConfig(
                route: 'auth/forgot-password',
                controller: [PasswordResetLinkController::class, 'create'],
                middleware: ['web', $guest],
            ),
            self::PasswordEmail => new HandlerConfig(
                route: 'auth/forgot-password',
                controller: [PasswordResetLinkController::class, 'store'],
                middleware: ['web', $guest],
            ),
            self::PasswordReset => new HandlerConfig(
                route: 'auth/reset-password/{token}',
                controller: [NewPasswordController::class, 'create'],
                middleware: ['web', $guest],
            ),
            self::PasswordUpdate => new HandlerConfig(
                route: 'auth/reset-password',
                controller: [NewPasswordController::class, 'store'],
                middleware: ['web', $guest],
            ),
            self::PasswordConfirm => new HandlerConfig(
                route: 'auth/user/confirm-password',
                controller: [ConfirmablePasswordController::class, 'show'],
                middleware: ['web', $authenticated],
            ),
            self::PasswordConfirmStore => new HandlerConfig(
                route: 'auth/user/confirm-password',
                controller: [ConfirmablePasswordController::class, 'store'],
                middleware: ['web', $authenticated],
            ),
            self::PasswordConfirmation => new HandlerConfig(
                route: 'auth/user/confirmed-password-status',
                controller: ShowConfirmedPasswordStatusController::class,
                middleware: ['web', $authenticated],
            ),
            self::VerificationNotice => new HandlerConfig(
                route: 'auth/email/verify',
                controller: EmailVerificationPromptController::class,
                middleware: ['web', $authenticated],
            ),
            self::VerificationVerify => new HandlerConfig(
                route: 'auth/email/verify/{id}/{hash}',
                controller: VerifyEmailController::class,
                middleware: ['web', $authenticated, 'signed', 'throttle:6,1'],
            ),
            self::VerificationSend => new HandlerConfig(
                route: 'auth/email/verification-notification',
                controller: SendEmailVerificationNotificationController::class,
                middleware: ['web', $authenticated, 'throttle:6,1'],
            ),
            self::TwoFactorLogin => new HandlerConfig(
                route: 'auth/two-factor-challenge',
                controller: [TwoFactorChallengeController::class, 'create'],
                middleware: ['web', $guest],
            ),
            self::TwoFactorLoginStore => new HandlerConfig(
                route: 'auth/two-factor-challenge',
                controller: [TwoFactorChallengeController::class, 'store'],
                middleware: ['web', $guest, 'throttle:5,1'],
            ),
            self::TwoFactorEnable => new HandlerConfig(
                route: 'auth/user/two-factor-authentication',
                controller: EnableTwoFactorAuthenticationController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorConfirm => new HandlerConfig(
                route: 'auth/user/confirmed-two-factor-authentication',
                controller: ConfirmTwoFactorAuthenticationController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorDisable => new HandlerConfig(
                route: 'auth/user/two-factor-authentication',
                controller: DisableTwoFactorAuthenticationController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorQrCode => new HandlerConfig(
                route: 'auth/user/two-factor-qr-code',
                controller: ShowTwoFactorQrCodeController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorSecretKey => new HandlerConfig(
                route: 'auth/user/two-factor-secret-key',
                controller: ShowTwoFactorSecretKeyController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorRecoveryCodes => new HandlerConfig(
                route: 'auth/user/two-factor-recovery-codes',
                controller: ShowRecoveryCodesController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::TwoFactorRegenerateRecoveryCodes => new HandlerConfig(
                route: 'auth/user/two-factor-recovery-codes',
                controller: RegenerateRecoveryCodesController::class,
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::PasskeyLoginOptions => new HandlerConfig(
                route: 'auth/passkeys/login/options',
                controller: [PasskeyLoginController::class, 'index'],
                middleware: ['web', $guest, 'throttle:5,1'],
            ),
            self::PasskeyLogin => new HandlerConfig(
                route: 'auth/passkeys/login',
                controller: [PasskeyLoginController::class, 'store'],
                middleware: ['web', $guest, 'throttle:5,1'],
            ),
            self::PasskeyConfirmOptions => new HandlerConfig(
                route: 'auth/passkeys/confirm/options',
                controller: [PasskeyConfirmationController::class, 'index'],
                middleware: ['web', $authenticated, 'throttle:5,1'],
            ),
            self::PasskeyConfirm => new HandlerConfig(
                route: 'auth/passkeys/confirm',
                controller: [PasskeyConfirmationController::class, 'store'],
                middleware: ['web', $authenticated, 'throttle:5,1'],
            ),
            self::PasskeyRegistrationOptions => new HandlerConfig(
                route: 'auth/user/passkeys/options',
                controller: [PasskeyRegistrationController::class, 'index'],
                middleware: ['web', $authenticated, $passwordConfirmed, 'throttle:5,1'],
            ),
            self::PasskeyStore => new HandlerConfig(
                route: 'auth/user/passkeys',
                controller: [PasskeyRegistrationController::class, 'store'],
                middleware: ['web', $authenticated, $passwordConfirmed, 'throttle:5,1'],
            ),
            self::PasskeyDestroy => new HandlerConfig(
                route: 'auth/user/passkeys/{passkey}',
                controller: [PasskeyRegistrationController::class, 'destroy'],
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::SocialRedirect => new HandlerConfig(
                route: 'auth/social/{provider}',
                controller: [SocialAuthenticationController::class, 'redirect'],
                middleware: ['web', $guest],
            ),
            self::SocialCallback => new HandlerConfig(
                route: 'auth/social/{provider}/callback',
                controller: [SocialAuthenticationController::class, 'callback'],
                middleware: [
                    EncryptCookies::class,
                    AddQueuedCookiesToResponse::class,
                    StartSession::class,
                    ShareErrorsFromSession::class,
                ],
            ),
            self::SocialLink => new HandlerConfig(
                route: 'auth/user/social/{provider}',
                controller: [LinkedAccountController::class, 'link'],
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::SocialDestroy => new HandlerConfig(
                route: 'auth/user/social/{socialAccount}',
                controller: [LinkedAccountController::class, 'destroy'],
                middleware: ['web', $authenticated, $passwordConfirmed],
            ),
            self::Jwks => new HandlerConfig(
                route: '.well-known/jwks.json',
                controller: JwksController::class,
                middleware: [],
            ),
            self::Discovery => new HandlerConfig(
                route: '.well-known/openid-configuration',
                controller: DiscoveryController::class,
                middleware: [],
            ),
            self::Userinfo => new HandlerConfig(
                route: 'oauth/userinfo',
                controller: UserinfoController::class,
                middleware: [],
            ),
            self::Logout => new HandlerConfig(
                route: 'oauth/logout',
                controller: EndSessionController::class,
                middleware: ['web'],
            ),
            self::Introspect => new HandlerConfig(
                route: 'oauth/introspect',
                controller: IntrospectionController::class,
                middleware: ['throttle'],
            ),
            self::Revoke => new HandlerConfig(
                route: 'oauth/revoke',
                controller: RevocationController::class,
                middleware: ['throttle'],
            ),
            self::Authorize => new HandlerConfig(
                route: 'oauth/authorize',
                controller: [AuthorizationController::class, 'authorize'],
                middleware: ['web'],
            ),
            self::IssueToken => new HandlerConfig(
                route: 'oauth/token',
                controller: [AccessTokenController::class, 'issueToken'],
                middleware: ['throttle'],
            ),
            self::TokenRefresh => new HandlerConfig(
                route: 'oauth/token/refresh',
                controller: [TransientTokenController::class, 'refresh'],
                middleware: ['web', $authenticated],
            ),
            self::Approve => new HandlerConfig(
                route: 'oauth/authorize',
                controller: [ApproveAuthorizationController::class, 'approve'],
                middleware: ['web', $authenticated],
            ),
            self::Deny => new HandlerConfig(
                route: 'oauth/authorize',
                controller: [DenyAuthorizationController::class, 'deny'],
                middleware: ['web', $authenticated],
            ),
        };
    }

    /**
     * The intrinsic HTTP verb(s) for this endpoint. An array is registered via
     * `Route::match`.
     *
     * @return string|array<int, string>
     */
    public function method(): string|array
    {
        return match ($this) {
            self::LoginStore,
            self::RegisterStore,
            self::PasswordEmail,
            self::PasswordUpdate,
            self::PasswordConfirmStore,
            self::VerificationSend,
            self::TwoFactorLoginStore,
            self::TwoFactorEnable,
            self::TwoFactorConfirm,
            self::TwoFactorRegenerateRecoveryCodes,
            self::PasskeyLogin,
            self::PasskeyConfirm,
            self::PasskeyStore,
            self::Introspect,
            self::Revoke,
            self::IssueToken,
            self::TokenRefresh,
            self::Approve => 'post',
            self::Deny, self::TwoFactorDisable, self::PasskeyDestroy, self::SocialDestroy => 'delete',
            self::Userinfo, self::Logout, self::SocialCallback => ['get', 'post'],
            default => 'get',
        };
    }
}
