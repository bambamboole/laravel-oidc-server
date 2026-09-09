<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Controllers;

use Illuminate\Http\Request;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class DenyAuthorizationController extends ApproveAuthorizationController
{
    /**
     * A completed deny surfaces as an OAuthServerException (rendered as the
     * error redirect to the client); an invalid auth_token throws before the
     * deny happened and is deliberately not audited.
     */
    public function deny(Request $request, ResponseInterface $psrResponse): Response
    {
        return $this->respondToInertia($request, $this->complete($request, $psrResponse, approved: false));
    }
}
