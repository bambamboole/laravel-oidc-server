<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Consents\Actions\CompleteAuthorization;
use Bambamboole\LaravelOidc\Server\Shared\Http\RespondsToInertiaExternalRedirects;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApproveConsentController
{
    use RespondsToInertiaExternalRedirects;

    public function __construct(protected CompleteAuthorization $complete) {}

    public function __invoke(Request $request): Response
    {
        return $this->respondToInertia($request, ($this->complete)($request, approved: true));
    }
}
