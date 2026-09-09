<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Actions;

use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Records the user's consent decision on the pending authorization request
 * and lets the authorization server complete it.
 */
final class CompleteAuthorization
{
    public function __construct(
        private readonly AuthorizationCompleter $completer,
        private readonly Auditor $auditor,
    ) {}

    public function __invoke(Request $request, bool $approved): Response
    {
        $completed = $this->completer->complete($request, $approved);

        $this->auditor->log(
            $approved ? AuditEventType::ConsentApproved : AuditEventType::ConsentDenied,
            userId: $completed->userId,
            clientId: $completed->clientId,
            context: ['scopes' => $completed->scopes],
        );

        return $completed->response;
    }
}
