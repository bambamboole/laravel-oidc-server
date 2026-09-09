<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Protocol;

use Symfony\Component\HttpFoundation\Response;

final readonly class CompletedAuthorization
{
    /** @param  list<string>  $scopes */
    public function __construct(
        public Response $response,
        public ?string $userId,
        public string $clientId,
        public array $scopes,
    ) {}
}
