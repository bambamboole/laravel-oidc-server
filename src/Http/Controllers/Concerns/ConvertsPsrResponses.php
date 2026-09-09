<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns;

use Psr\Http\Message\ResponseInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Response;

trait ConvertsPsrResponses
{
    public function convertResponse(ResponseInterface $psrResponse): Response
    {
        return (new HttpFoundationFactory)->createResponse($psrResponse);
    }
}
