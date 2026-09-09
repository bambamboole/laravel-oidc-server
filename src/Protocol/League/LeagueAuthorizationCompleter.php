<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\League;

use Bambamboole\LaravelOidc\Server\Protocol\OAuthServerException;
use Bambamboole\LaravelOidc\Server\Shared\Http\ConvertsPsrResponses;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\AuthorizationCompleter;
use Bambamboole\LaravelOidc\Server\Shared\Protocol\CompletedAuthorization;
use Illuminate\Http\Request;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;
use Psr\Http\Message\ResponseInterface;

final class LeagueAuthorizationCompleter implements AuthorizationCompleter
{
    use ConvertsPsrResponses, RetrievesAuthRequestFromSession;

    public function __construct(private readonly AuthorizationServer $server) {}

    public function complete(Request $request, bool $approved): CompletedAuthorization
    {
        $authRequest = $this->getAuthRequestFromSession($request);
        $authRequest->setAuthorizationApproved($approved);

        try {
            $response = $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, app(ResponseInterface::class)),
            );
        } catch (LeagueException $exception) {
            // A denial completes as the error redirect to the client.
            $response = (new OAuthServerException($exception, $authRequest->getGrantTypeId() === 'implicit'))->getResponse();
        }

        return new CompletedAuthorization(
            response: $response,
            userId: $authRequest->getUser()?->getIdentifier(),
            clientId: $authRequest->getClient()->getIdentifier(),
            scopes: array_values(array_map(
                fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
                $authRequest->getScopes(),
            )),
        );
    }
}
