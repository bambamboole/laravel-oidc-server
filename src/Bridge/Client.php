<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Bridge;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * `identifier` is the client_id relying parties send; `key` is the row's
 * primary key, which the token repositories persist. They differ so a client
 * can be renamed without rewriting its tokens.
 */
class Client implements ClientEntityInterface
{
    use ClientTrait, EntityTrait;

    /**
     * @param  array<int, string>  $redirectUri
     * @param  array<int, string>  $grantTypes
     */
    public function __construct(
        string $identifier,
        ?string $name = null,
        array $redirectUri = [],
        bool $isConfidential = false,
        public readonly ?string $key = null,
        public readonly ?string $provider = null,
        public readonly array $grantTypes = [],
    ) {
        $this->setIdentifier($identifier);

        if ($name !== null) {
            $this->name = $name;
        }

        $this->isConfidential = $isConfidential;
        $this->redirectUri = $redirectUri;
    }

    public function supportsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /** The value foreign keys store; falls back to the identifier for hand-built entities. */
    public function storageKey(): string
    {
        return $this->key ?? $this->getIdentifier();
    }
}
