<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use Laravel\Passport\Exceptions\OAuthServerException;
use Laravel\Passport\Http\Controllers\DenyAuthorizationController as PassportDenyAuthorizationController;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class DenyAuthorizationController extends PassportDenyAuthorizationController
{
    use RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    /**
     * A completed deny surfaces as Passport's OAuthServerException (rendered
     * as the error redirect to the client), so the audit hooks into the
     * catch; an invalid auth_token throws before the deny happened and is
     * deliberately not audited.
     */
    public function deny(Request $request, ResponseInterface $psrResponse): Response
    {
        $authRequest = $this->peekAuthRequestFromSession($request);

        try {
            $response = $this->respondToInertia($request, parent::deny($request, $psrResponse));
        } catch (OAuthServerException $exception) {
            $this->recordDenied($authRequest);

            throw $exception;
        }

        $this->recordDenied($authRequest);

        return $response;
    }

    private function recordDenied(?AuthorizationRequestInterface $authRequest): void
    {
        app(Auditor::class)->log(
            AuditEventType::ConsentDenied,
            userId: $authRequest?->getUser()?->getIdentifier(),
            clientId: $authRequest?->getClient()->getIdentifier(),
            context: $authRequest === null ? [] : [
                'scopes' => array_map(
                    fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                    $authRequest->getScopes(),
                ),
            ],
        );
    }
}
