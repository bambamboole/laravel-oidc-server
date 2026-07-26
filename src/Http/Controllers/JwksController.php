<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Token\Jwk;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Illuminate\Http\JsonResponse;

class JwksController
{
    public function __invoke(): JsonResponse
    {
        $keys = [];

        foreach (SigningKeys::verificationKeys() as $pem) {
            $jwk = Jwk::fromPem($pem);
            $keys[$jwk['kid']] = $jwk;
        }

        return response()
            ->json(['keys' => array_values($keys)])
            ->header('Cache-Control', 'max-age=3600, public');
    }
}
