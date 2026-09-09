<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Concerns;

use Bambamboole\LaravelOidc\Server\Protocol\OAuthServerException;
use Closure;
use League\OAuth2\Server\Exception\OAuthServerException as LeagueException;

trait HandlesOAuthErrors
{
    /**
     * @template TReturn
     *
     * @param  Closure(): TReturn  $callback
     * @return TReturn
     */
    protected function withErrorHandling(Closure $callback, bool $useFragment = false)
    {
        try {
            return $callback();
        } catch (LeagueException $exception) {
            throw new OAuthServerException($exception, $useFragment);
        }
    }
}
