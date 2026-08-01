<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use Laravel\Passport\Http\Controllers\DenyAuthorizationController as PassportDenyAuthorizationController;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class DenyAuthorizationController extends PassportDenyAuthorizationController
{
    use RespondsToInertiaExternalRedirects, RetrievesAuthRequestFromSession;

    public function deny(Request $request, ResponseInterface $psrResponse): Response
    {
        return $this->respondToInertia($request, parent::deny($request, $psrResponse));
    }
}
