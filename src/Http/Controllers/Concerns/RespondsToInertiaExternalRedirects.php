<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The consent screen (Approve/Deny) is the last page the SPA owns before
 * control hands off to the client's redirect_uri — including custom-scheme
 * URIs an XHR can't navigate to at all. Inertia can't follow an XHR redirect
 * off-app (https://inertiajs.com/redirects#external-redirects), so a plain
 * 302 here is silently swallowed by the client-side visit. Converting it to
 * Inertia's 409 + X-Inertia-Location protocol makes the client do a real
 * window.location navigation instead.
 */
trait RespondsToInertiaExternalRedirects
{
    private function respondToInertia(Request $request, Response $response): Response
    {
        if (! $request->hasHeader('X-Inertia') || ! $response->isRedirect() || ! $response->headers->has('Location')) {
            return $response;
        }

        return response('', 409, ['X-Inertia-Location' => $response->headers->get('Location')]);
    }
}
