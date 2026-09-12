<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Clients\Actions\RegisterClient;
use Bambamboole\LaravelOidc\Server\Clients\Exceptions\ClientRegistrationException;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;

/**
 * RFC 7591 dynamic client registration endpoint. The response echoes every
 * registered metadata value (§3.2.1); a confidential client's response also
 * carries `client_secret` with `client_secret_expires_at` 0 (never).
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
        ];

        if ($client->secret !== null) {
            $response['client_secret'] = $client->secret;
            $response['client_secret_expires_at'] = 0;
        }

        $response += [
            'client_name' => (string) $client->getAttribute('name'),
            'redirect_uris' => $client->redirect_uris,
            'post_logout_redirect_uris' => $client->post_logout_redirect_uris ?? [],
            'grant_types' => $client->grant_types,
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $client->token_endpoint_auth_method->value,
        ];

        if ($client->backchannel_logout_uri !== null) {
            $response['backchannel_logout_uri'] = $client->backchannel_logout_uri;
            $response['backchannel_logout_session_required'] = $client->backchannel_logout_session_required;
        }

        $scopes = $client->assignedScopes();

        // MCP clients send this value back as the authorize `scope`, where `*`
        // is not a scope: a client that may request everything gets no hint.
        if ($scopes !== [] && ! in_array('*', $scopes, true)) {
            $response['scope'] = implode(' ', $scopes);
        }

        return response()->json($response, 201);
    }
}
