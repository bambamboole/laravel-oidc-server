<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers;

use Bambamboole\LaravelOidc\Server\Token\Jwk;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Illuminate\Http\JsonResponse;

class JwksController
{
    public function __construct(private readonly SigningKeys $signingKeys) {}

    public function __invoke(): JsonResponse
    {
        $keys = [];

        foreach ($this->signingKeys->verificationKeys() as $key) {
            $jwk = Jwk::fromPem($key->publicKeyPem);
            $jwk['kid'] = $key->kid();
            $keys[$jwk['kid']] = $jwk;
        }

        return response()
            ->json(['keys' => array_values($keys)])
            ->header('Cache-Control', 'max-age=3600, public');
    }
}
