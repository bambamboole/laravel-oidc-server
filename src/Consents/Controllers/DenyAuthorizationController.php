<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Controllers;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class DenyAuthorizationController extends ApproveAuthorizationController
{
    public function deny(Request $request): Response
    {
        return $this->respondToInertia($request, ($this->complete)($request, approved: false));
    }
}
