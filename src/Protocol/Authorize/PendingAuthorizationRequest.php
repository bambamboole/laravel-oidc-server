<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Shared\Authentication\PendingAuthorization;
use Illuminate\Http\Request;

final readonly class PendingAuthorizationRequest implements PendingAuthorization
{
    public function __construct(private AuthorizeRequestSession $session) {}

    public function clientId(Request $request): ?string
    {
        return $this->session->peek($request)?->clientId;
    }

    public function scopes(Request $request): array
    {
        $authorizeRequest = $this->session->peek($request);

        return $authorizeRequest instanceof AuthorizeRequest ? $authorizeRequest->scopes : [];
    }
}
