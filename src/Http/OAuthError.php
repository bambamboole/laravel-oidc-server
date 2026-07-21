<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http;

use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Response;

final class OAuthError
{
    public static function bearer(string $error, int $status, ?string $description = null, bool $withRealm = false): never
    {
        $challenge = 'Bearer '.($withRealm ? 'realm="OIDC", ' : '')."error=\"{$error}\"";
        $body = ['error' => $error];

        if ($description !== null) {
            $body['error_description'] = $description;
        }

        throw new HttpResponseException(
            Response::json($body, $status)->withHeaders(['WWW-Authenticate' => $challenge]),
        );
    }

    public static function client(?string $description = null): never
    {
        $body = ['error' => 'invalid_client'];

        if ($description !== null) {
            $body['error_description'] = $description;
        }

        throw new HttpResponseException(
            Response::json($body, 401)->withHeaders(['WWW-Authenticate' => 'Basic realm="OIDC"']),
        );
    }
}
