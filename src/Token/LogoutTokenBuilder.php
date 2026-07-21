<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Token;

use Bambamboole\LaravelOidc\Auth\Models\OidcSession;
use Bambamboole\LaravelOidc\Issuer;
use DateTimeImmutable;

class LogoutTokenBuilder
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function build(OidcSession $session, string $clientId): string
    {
        $config = SigningKeys::signingConfiguration();

        $now = new DateTimeImmutable;

        $token = $config->builder()
            ->withHeader('typ', 'logout+jwt')
            ->withHeader('kid', SigningKeys::signingKid())
            ->issuedBy(Issuer::url())
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
