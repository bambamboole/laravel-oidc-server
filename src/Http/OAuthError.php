<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http;

use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Response;

final class OAuthError
{
    public static function bearer(string $error, int $status, bool $withRealm = false): never
    {
        $challenge = 'Bearer '.($withRealm ? 'realm="OIDC", ' : '')."error=\"{$error}\"";

        throw new HttpResponseException(
            Response::json(['error' => $error], $status)->withHeaders(['WWW-Authenticate' => $challenge]),
        );
    }

    public static function client(): never
    {
        throw new HttpResponseException(
            Response::json(['error' => 'invalid_client'], 401)->withHeaders(['WWW-Authenticate' => 'Basic realm="OIDC"']),
        );
    }
}
