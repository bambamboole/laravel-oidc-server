<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Actions;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Consents\ConsentRepository;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Shared\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * An approval is remembered so the next request for the same client and
 * scopes skips the consent screen.
 */
final readonly class CompleteAuthorization
{
    public function __construct(
        private AuthorizationCompleter $completer,
        private ConsentRepository $consents,
        private ClientRepository $clients,
        private Auditor $auditor,
    ) {}

    public function __invoke(Request $request, bool $approved): Response
    {
        $completed = $this->completer->complete($request, $approved);

        if ($approved && $completed->userId !== null) {
            $client = $this->clients->find($completed->clientId);

            if ($client instanceof Client) {
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
