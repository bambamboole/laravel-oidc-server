<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Actions;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Records the user's consent decision on the pending authorization request
 * and lets the authorization server complete it. A denial completes as an
 * OAuthServerException (the error redirect to the client), so the audit
 * event is recorded before it propagates.
 */
final class CompleteAuthorization
{
    public function __construct(
        private readonly AuthorizationServer $server,
        private readonly Auditor $auditor,
    ) {}

    /**
     * @throws OAuthServerException
     */
    public function __invoke(AuthorizationRequestInterface $authRequest, ResponseInterface $psrResponse, bool $approved): ResponseInterface
    {
        $authRequest->setAuthorizationApproved($approved);

        try {
            $response = $this->server->completeAuthorizationRequest($authRequest, $psrResponse);
        } catch (OAuthServerException $exception) {
            $this->audit($authRequest, $approved);

            throw $exception;
        }

        $this->audit($authRequest, $approved);

        return $response;
    }

    private function audit(AuthorizationRequestInterface $authRequest, bool $approved): void
    {
        $this->auditor->log(
            $approved ? AuditEventType::ConsentApproved : AuditEventType::ConsentDenied,
            userId: $authRequest->getUser()?->getIdentifier(),
            clientId: $authRequest->getClient()->getIdentifier(),
            context: [
                'scopes' => array_map(
                    fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                    $authRequest->getScopes(),
                ),
            ],
        );
    }
}
