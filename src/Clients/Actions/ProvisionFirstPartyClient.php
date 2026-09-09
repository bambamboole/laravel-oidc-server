<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Actions;

use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningResult;
use SensitiveParameter;

final class ProvisionFirstPartyClient
{
    public function __construct(private readonly FirstPartyClientProvisioner $provisioner) {}

    /**
     * @param  string[]  $redirectUris
     * @param  string[]  $postLogoutRedirectUris
     * @param  string[]  $allowedExchangeAudiences
     */
    public function __invoke(
        string $name,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $allowedExchangeAudiences = [],
        ?string $adoptClientId = null,
        bool $rotateSecret = false,
        #[SensitiveParameter] ?string $existingClientSecret = null,
    ): FirstPartyClientProvisioningResult {
        return $this->provisioner->provision(
            $name,
            $redirectUris,
            $postLogoutRedirectUris,
            $allowedExchangeAudiences,
            $adoptClientId,
            $rotateSecret,
            $existingClientSecret,
        );
    }
}
