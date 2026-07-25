<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Facades;

use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioningResult;
use Bambamboole\LaravelOidc\OidcManager;
use Closure;
use Illuminate\Support\Facades\Facade;
use RuntimeException;
use SensitiveParameter;

/**
 * @method static void postLogin(Closure $hook)
 * @method static void clientCredentials(Closure $trigger)
 * @method static void tokenExchange(Closure $trigger)
 * @method static void personalAccessToken(Closure $trigger)
 * @method static void authorizationCode(Closure $trigger)
 * @method static void createUsersUsing(callable|string $action)
 * @method static void resetUserPasswordsUsing(callable|string $action)
 * @method static void createUsersFromSocialUsing(callable|string $action)
 * @method static array<string, \Bambamboole\LaravelOidc\Auth\Social\Contracts\SocialProvider> socialProviders()
 * @method static void extendSocialProvider(string $driver, Closure $creator)
 * @method static \Bambamboole\LaravelOidc\Exchange\IssuedToken issueScopedToken(string $audience, string[] $scopes)
 * @method static string issuer()
 * @method static \Bambamboole\LaravelOidc\Routing\HandlerConfig|false handlerConfig(\Bambamboole\LaravelOidc\Routing\Handler $handler)
 *
 * @see OidcManager
 */
class Oidc extends Facade
{
    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     */
    public static function provisionFirstPartyClient(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $allowedExchangeAudiences = [],
        ?string $adoptClientId = null,
        bool $rotateSecret = false,
        #[SensitiveParameter] ?string $existingClientSecret = null,
    ): FirstPartyClientProvisioningResult {
        $manager = static::getFacadeRoot();

        if (! $manager instanceof OidcManager) {
            throw new RuntimeException('The OIDC manager is not available.');
        }

        return $manager->provisionFirstPartyClient(
            $name,
            $redirectUris,
            $postLogoutRedirectUris,
            $allowedExchangeAudiences,
            $adoptClientId,
            $rotateSecret,
            $existingClientSecret,
        );
    }

    protected static function getFacadeAccessor(): string
    {
        return OidcManager::class;
    }
}
