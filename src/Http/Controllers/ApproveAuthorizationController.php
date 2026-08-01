<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use Laravel\Passport\Http\Controllers\ApproveAuthorizationController as PassportApproveAuthorizationController;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ApproveAuthorizationController extends PassportApproveAuthorizationController
{
    use RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    public function approve(Request $request, ResponseInterface $psrResponse): Response
    {
        return $this->respondToInertia($request, parent::approve($request, $psrResponse));
    }
}
