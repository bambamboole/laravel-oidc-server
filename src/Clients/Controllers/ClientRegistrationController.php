<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\Actions\RegisterClient;
use Bambamboole\LaravelOidc\Server\Clients\ClientRegistrationException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/**
 * RFC 7591 dynamic client registration endpoint.
 */
class ClientRegistrationController
{
    public function __invoke(Request $request, RegisterClient $register, RealmResolver $realms): JsonResponse
    {
        abort_unless($realms->current()->clients()->dynamicRegistration, 404);

        try {
            $client = $register($request->all());
        } catch (ClientRegistrationException $exception) {
            return response()->json([
                'error' => $exception->error,
                'error_description' => $exception->getMessage(),
            ], 400);
        }

        $response = [
            'client_id' => $client->client_id,
            'client_id_issued_at' => Carbon::now()->getTimestamp(),
            'client_secret_expires_at' => 0,
            'client_name' => (string) $client->getAttribute('name'),
            'redirect_uris' => $client->redirect_uris,
            'grant_types' => $client->getAttribute('grant_types'),
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $client->token_endpoint_auth_method->value,
        ];

        $scopes = $client->getAttribute('scopes');

        if (is_array($scopes) && $scopes !== []) {
            $response['scope'] = implode(' ', $scopes);
        }

        return response()->json($response, 201);
    }
}
