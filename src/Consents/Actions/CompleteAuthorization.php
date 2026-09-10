<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Actions;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Consents\ConsentRepository;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Lets the authorization server complete the pending authorization request
 * with the user's decision, and on approval remembers the consent so the
 * next request for the same client and scopes skips the screen.
 */
final class CompleteAuthorization
{
    public function __construct(
        private readonly AuthorizationCompleter $completer,
        private readonly ConsentRepository $consents,
        private readonly ClientRepository $clients,
        private readonly Auditor $auditor,
    ) {}

    public function __invoke(Request $request, bool $approved): Response
    {
        $completed = $this->completer->complete($request, $approved);

        if ($approved && $completed->userId !== null) {
            $client = $this->clients->find($completed->clientId);

            if ($client !== null) {
                $this->consents->grant($completed->userId, (string) $client->getKey(), $completed->scopes);
            }
        }

        $this->auditor->log(
            $approved ? AuditEventType::ConsentApproved : AuditEventType::ConsentDenied,
            userId: $completed->userId,
            clientId: $completed->clientId,
            context: ['scopes' => $completed->scopes],
        );

        return $completed->response;
    }
}
