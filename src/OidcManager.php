<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server;

use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\AccessTokenPipeline;
use Bambamboole\LaravelOidc\Server\Authentication\Pipeline\PostLoginPipeline;
use Bambamboole\LaravelOidc\Server\Brokering\Contracts\SocialProvider;
use Bambamboole\LaravelOidc\Server\Brokering\SocialProviderRegistry;
use Bambamboole\LaravelOidc\Server\Clients\Client;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientConfig;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningResult;
use Bambamboole\LaravelOidc\Server\Exchange\IssuedToken;
use Bambamboole\LaravelOidc\Server\Exchange\TokenExchanger;
use Bambamboole\LaravelOidc\Server\Scopes\ScopeRegistry;
use Bambamboole\LaravelOidc\Server\Session\SessionTokenProvider;
use Bambamboole\LaravelOidc\Server\Token\CurrentAccessToken;
use Bambamboole\LaravelOidc\Server\Token\Token;
use Bambamboole\LaravelOidc\Server\User\OAuthenticatable;
use Bambamboole\LaravelOidc\Server\User\UserActionManager;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use RuntimeException;
use SensitiveParameter;

/**
 * Collaborators are resolved lazily so registering hooks through the Oidc
 * facade in a host app's provider boot() never pulls the signing-key or
 * encrypter graph.
 */
class OidcManager
{
    public function __construct(private readonly Container $app) {}

    /**
     * Register scopes the provider understands, on top of `oidc.scopes.catalog`.
     *
     * @param  array<string, string>  $scopes
     */
    public function tokensCan(array $scopes): void
    {
        ScopeRegistry::tokensCan($scopes);
    }

    /**
     * Authenticate a user for the given guard with a token that grants the
     * listed scopes, without persisting anything. Test-time only.
     *
     * @param  list<string>  $scopes
     */
    public function actingAs(Authenticatable $user, array $scopes = [], string $guard = 'oidc'): Authenticatable
    {
        if ($user instanceof OAuthenticatable) {
            $user->withAccessToken(new CurrentAccessToken(new Token(['scopes' => $scopes])));
        }

        $auth = $this->app->make('auth');
        $auth->guard($guard)->setUser($user);
        $auth->shouldUse($guard);

        return $user;
    }

    public function createUsersUsing(callable|string $action): void
    {
        $this->userActions()->createUsersUsing($action);
    }

    public function resetUserPasswordsUsing(callable|string $action): void
    {
        $this->userActions()->resetUserPasswordsUsing($action);
    }

    public function createUsersFromSocialUsing(callable|string $action): void
    {
        $this->userActions()->createUsersFromSocialUsing($action);
    }

    /**
     * The social providers that are configured and credentialed, keyed by
     * provider key — for rendering login buttons.
     *
     * @return array<string, SocialProvider>
     */
    public function socialProviders(): array
    {
        return $this->socialProviderRegistry()->enabled();
    }

    public function extendSocialProvider(string $driver, Closure $creator): void
    {
        $this->socialProviderRegistry()->extend($driver, $creator);
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
        return $this->app->make(FirstPartyClientProvisioner::class)->provision(
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
        $this->app->make(PostLoginPipeline::class)->register($hook);
    }

    public function clientCredentials(Closure $trigger): void
    {
        $this->accessTokenPipeline()->register('client_credentials', $trigger);
    }

    public function tokenExchange(Closure $trigger): void
    {
        $this->accessTokenPipeline()->register('token_exchange', $trigger);
    }

    public function personalAccessToken(Closure $trigger): void
    {
        $this->accessTokenPipeline()->register('personal_access_token', $trigger);
    }

    public function authorizationCode(Closure $trigger): void
    {
        $this->accessTokenPipeline()->register('authorization_code', $trigger);
    }

    /**
     * @param  string[]  $scopes
     */
    public function issueScopedToken(string $audience, array $scopes): IssuedToken
    {
        $subject = $this->app->make(SessionTokenProvider::class)->currentToken();

        if ($subject === null) {
            throw new RuntimeException('No session token is available for the current user.');
        }

        $client = Client::query()->find($this->app->make(FirstPartyClientConfig::class)->clientId());

        if ($client === null) {
            throw new RuntimeException('The oidc.first_party.client_id is not configured or does not exist.');
        }

        $token = $this->app->make(TokenExchanger::class)->exchange($subject, $client, $audience, $scopes);

        return IssuedToken::fromEntity($token, $audience);
    }

    private function userActions(): UserActionManager
    {
        return $this->app->make(UserActionManager::class);
    }

    private function socialProviderRegistry(): SocialProviderRegistry
    {
        return $this->app->make(SocialProviderRegistry::class);
    }

    private function accessTokenPipeline(): AccessTokenPipeline
    {
        return $this->app->make(AccessTokenPipeline::class);
    }
}
