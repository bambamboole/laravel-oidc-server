<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Grant;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class OidcAuthorizationRequest extends AuthorizationRequest
{
    private ?string $nonce = null;

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }
}
