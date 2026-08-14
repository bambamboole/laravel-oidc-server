<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use Laravel\Passport\Http\Controllers\ApproveAuthorizationController as PassportApproveAuthorizationController;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ApproveAuthorizationController extends PassportApproveAuthorizationController
{
    use RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    public function approve(Request $request, ResponseInterface $psrResponse): Response
    {
        $authRequest = $this->peekAuthRequestFromSession($request);
        $response = $this->respondToInertia($request, parent::approve($request, $psrResponse));

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
}
