<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\CompletedAuthorization;
use Illuminate\Http\Request;

final readonly class CompleteAuthorizeRequest implements AuthorizationCompleter
{
    public function __construct(
        private AuthorizeRequestSession $session,
        private AuthorizationCodeIssuer $codes,
    ) {}

    public function complete(Request $request, bool $approved): CompletedAuthorization
    {
        $authorizeRequest = $this->session->pull($request);

        return new CompletedAuthorization(
            response: $approved ? $this->codes->approve($authorizeRequest) : $this->codes->deny($authorizeRequest),
            userId: $authorizeRequest->userId,
            clientId: $authorizeRequest->clientId,
            scopes: $authorizeRequest->scopes,
        );
    }
}
