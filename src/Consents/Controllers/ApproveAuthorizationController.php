<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Controllers;

use Bambamboole\LaravelOidc\Server\Consents\Actions\CompleteAuthorization;
use Bambamboole\LaravelOidc\Server\Protocol\Concerns\ConvertsPsrResponses;
use Bambamboole\LaravelOidc\Server\Protocol\Concerns\HandlesOAuthErrors;
use Bambamboole\LaravelOidc\Server\Protocol\Concerns\RespondsToInertiaExternalRedirects;
use Bambamboole\LaravelOidc\Server\Protocol\League\RetrievesAuthRequestFromSession;
use Illuminate\Http\Request;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ApproveAuthorizationController
{
    use ConvertsPsrResponses, HandlesOAuthErrors, RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    public function __construct(protected CompleteAuthorization $complete) {}

    public function approve(Request $request, ResponseInterface $psrResponse): Response
    {
        return $this->respondToInertia($request, $this->complete($request, $psrResponse, approved: true));
    }

    protected function complete(Request $request, ResponseInterface $psrResponse, bool $approved): Response
    {
        $authRequest = $this->getAuthRequestFromSession($request);

        return $this->withErrorHandling(fn (): Response => $this->convertResponse(
            ($this->complete)($authRequest, $psrResponse, $approved)
        ), $authRequest->getGrantTypeId() === 'implicit');
    }
}
