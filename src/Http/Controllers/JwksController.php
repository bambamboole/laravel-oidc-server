<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Bambamboole\LaravelOidc\Token\Jwk;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Illuminate\Http\JsonResponse;

class JwksController
{
    public function __invoke(): JsonResponse
    {
        $keys = [];

        foreach ([SigningKeys::publicKey(), ...config('oidc.additional_public_keys', [])] as $pem) {
            $jwk = Jwk::fromPem($pem);
            $keys[$jwk['kid']] = $jwk;
        }

        return response()
            ->json(['keys' => array_values($keys)])
            ->header('Cache-Control', 'max-age=3600, public');
    }
}
