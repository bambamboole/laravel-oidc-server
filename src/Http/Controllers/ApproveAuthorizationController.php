<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\ConvertsPsrResponses;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\HandlesOAuthErrors;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ApproveAuthorizationController
{
    use ConvertsPsrResponses, HandlesOAuthErrors, RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    public function __construct(protected AuthorizationServer $server) {}

    public function approve(Request $request, ResponseInterface $psrResponse): Response
    {
        $authRequest = $this->peekAuthRequestFromSession($request);
        $response = $this->respondToInertia($request, $this->complete($request, $psrResponse, approved: true));

        app(Auditor::class)->log(
            AuditEventType::ConsentApproved,
            userId: $authRequest?->getUser()?->getIdentifier(),
            clientId: $authRequest?->getClient()->getIdentifier(),
            context: $authRequest === null ? [] : [
                'scopes' => array_map(
                    fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                    $authRequest->getScopes(),
                ),
            ],
        );

        return $response;
    }

    protected function complete(Request $request, ResponseInterface $psrResponse, bool $approved): Response
    {
        $authRequest = $this->getAuthRequestFromSession($request);
        $authRequest->setAuthorizationApproved($approved);

        return $this->withErrorHandling(fn (): Response => $this->convertResponse(
            $this->server->completeAuthorizationRequest($authRequest, $psrResponse)
        ), $authRequest->getGrantTypeId() === 'implicit');
    }
}
