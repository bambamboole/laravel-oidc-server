<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol;

use Bambamboole\LaravelOidc\Server\Shared\Tokens\MintedAccessToken;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;

/**
 * RFC 6749 §5.1 successful token response.
 */
final readonly class TokenResponse implements Responsable
{
    /** @param  array<string, mixed>  $extra  grant-specific members such as RFC 8693's issued_token_type */
    public function __construct(
        public MintedAccessToken $accessToken,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public array $extra = [],
    ) {}

    public function toResponse($request): JsonResponse
    {
        $body = [
            'token_type' => 'Bearer',
            'expires_in' => max(0, $this->accessToken->expiresAt->getTimestamp() - time()),
            'access_token' => $this->accessToken->jwt,
        ];

        if ($this->refreshToken !== null) {
            $body['refresh_token'] = $this->refreshToken;
        }

        if ($this->idToken !== null) {
            $body['id_token'] = $this->idToken;
        }

        return new JsonResponse([...$body, ...$this->extra], 200, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }
}
