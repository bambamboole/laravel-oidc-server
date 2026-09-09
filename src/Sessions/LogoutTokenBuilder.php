<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Sessions;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use DateTimeImmutable;

class LogoutTokenBuilder
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private readonly IssuerResolver $issuer,
        private readonly SigningKeys $signingKeys,
    ) {}

    public function build(OidcSession $session, string $clientId): string
    {
        $config = $this->signingKeys->signingConfiguration();

        $now = new DateTimeImmutable;

        $token = $config->builder()
            ->withHeader('typ', 'logout+jwt')
            ->withHeader('kid', $this->signingKeys->signingKid())
            ->issuedBy($this->issuer->url())
            ->permittedFor($clientId)
            ->identifiedBy(bin2hex(random_bytes(16)))
            ->issuedAt($now)
            ->expiresAt($now->modify('+120 seconds'))
            ->relatedTo($session->user_id)
            ->withClaim('sid', $session->sid)
            ->withClaim('events', (object) [self::EVENT => (object) []])
            ->getToken($config->signer(), $config->signingKey());

        return $token->toString();
    }
}
