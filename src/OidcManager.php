<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc;

use Bambamboole\LaravelOidc\Auth\AuthViewManager;
use Bambamboole\LaravelOidc\Auth\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Auth\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Auth\Social\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Auth\UserActionManager;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioningResult;
use Bambamboole\LaravelOidc\Contracts\SessionTokenProvider;
use Bambamboole\LaravelOidc\Exchange\IssuedToken;
use Bambamboole\LaravelOidc\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Routing\Handler;
use Bambamboole\LaravelOidc\Routing\HandlerConfig;
use Closure;
use Laravel\Passport\Passport;
use RuntimeException;
use SensitiveParameter;

class OidcManager
{
    public function __construct(
        private readonly SessionTokenProvider $sessionTokens,
        private readonly TokenExchanger $exchanger,
        private readonly AuthViewManager $authViews,
        private readonly UserActionManager $userActions,
        private readonly PostLoginPipeline $pipeline,
        private readonly AccessTokenPipeline $accessTokenPipeline,
        private readonly FirstPartyClientProvisioner $firstPartyClientProvisioner,
        private readonly SocialProviderRegistry $socialProviders,
    ) {}

    /**
     * The issuer URL advertised in discovery and stamped into every token.
     */
    public function issuer(): string
    {
        return Issuer::url();
    }

    /**
     * Resolve the configuration for a route handler, or `false` when it is
     * disabled (or not present in config).
     */
    public function handlerConfig(Handler $handler): HandlerConfig|false
    {
        return $handler->config();
    }

    public function loginView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::Login, $view);
    }

    public function confirmPasswordView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::ConfirmPassword, $view);
    }

    public function registerView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::Register, $view);
    }

    public function requestPasswordResetLinkView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::RequestPasswordResetLink, $view);
    }

    public function resetPasswordView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::ResetPassword, $view);
    }

    public function verifyEmailView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::VerifyEmail, $view);
    }

    public function twoFactorChallengeView(Closure $view): void
    {
        $this->authViews->bind(AuthViewManager::TwoFactorChallenge, $view);
    }

    public function createUsersUsing(callable|string $action): void
    {
        $this->userActions->createUsersUsing($action);
    }

    public function resetUserPasswordsUsing(callable|string $action): void
    {
        $this->userActions->resetUserPasswordsUsing($action);
    }

    public function createUsersFromSocialUsing(callable|string $action): void
    {
        $this->userActions->createUsersFromSocialUsing($action);
    }

    /**
     * The social providers that are configured and credentialed, keyed by
     * provider key — for rendering login buttons.
     *
     * @return array<string, SocialProvider>
     */
    public function socialProviders(): array
    {
        return $this->socialProviders->enabled();
    }

    public function extendSocialProvider(string $driver, Closure $creator): void
    {
        $this->socialProviders->extend($driver, $creator);
    }

    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     */
    public function provisionFirstPartyClient(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $allowedExchangeAudiences = [],
        ?string $adoptClientId = null,
        bool $rotateSecret = false,
        #[SensitiveParameter] ?string $existingClientSecret = null,
    ): FirstPartyClientProvisioningResult {
        return $this->firstPartyClientProvisioner->provision(
            $name,
            $redirectUris,
            $postLogoutRedirectUris,
            $allowedExchangeAudiences,
            $adoptClientId,
            $rotateSecret,
            $existingClientSecret,
        );
    }

    public function postLogin(Closure $hook): void
    {
        $this->pipeline->register($hook);
    }

    public function clientCredentials(Closure $trigger): void
    {
        $this->accessTokenPipeline->registerClientCredentials($trigger);
    }

    public function tokenExchange(Closure $trigger): void
    {
        $this->accessTokenPipeline->registerTokenExchange($trigger);
    }

    public function personalAccessToken(Closure $trigger): void
    {
        $this->accessTokenPipeline->registerPersonalAccessToken($trigger);
    }

    public function authorizationCode(Closure $trigger): void
    {
        $this->accessTokenPipeline->registerAuthorizationCode($trigger);
    }

    /**
     * @param  string[]  $scopes
     */
    public function issueScopedToken(string $audience, array $scopes): IssuedToken
    {
        $subject = $this->sessionTokens->currentToken();

        if ($subject === null) {
            throw new RuntimeException('No session token is available for the current user.');
        }

        $client = Passport::client()->newQuery()->find(app(FirstPartyClientConfig::class)->clientId());

        if ($client === null) {
            throw new RuntimeException('The oidc.first_party.client_id is not configured or does not exist.');
        }

        $token = $this->exchanger->exchange($subject, $client, $audience, $scopes);

        return IssuedToken::fromEntity($token, $audience);
    }
}
