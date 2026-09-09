<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Consents\Views;

use Bambamboole\LaravelOidc\Server\Shared\Consents\AuthorizationViewResponse;
use Illuminate\Contracts\Support\Responsable;

/**
 * Renders consent through the same view seam as every other auth surface. The
 * view is resolved when consent is actually rendered, not when the response is
 * constructed — most authorize requests skip consent entirely, and an
 * unbound view must not break them.
 */
class ConsentViewResponse implements AuthorizationViewResponse
{
    /** @var array<string, mixed> */
    protected array $parameters = [];

    /** @param  array<string, mixed>  $parameters */
    public function withParameters(array $parameters = []): static
    {
        $this->parameters = $parameters;

        return $this;
    }

    public function toResponse($request)
    {
        $response = app(ConsentView::class)->respond(
            new ConsentPrompt(
                client: $this->parameters['client'],
                user: $this->parameters['user'],
                scopes: $this->parameters['scopes'],
                authToken: $this->parameters['authToken'],
            ),
            $request,
        );

        return $response instanceof Responsable
            ? $response->toResponse($request)
            : $response;
    }
}
