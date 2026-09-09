<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * Every realm is its own OpenID Provider, so each gets its own issuer below
 * the deployment's origin. The configured issuer supplies that origin.
 */
final readonly class RealmIssuerResolver implements IssuerResolver
{
    public function __construct(private RealmResolver $realms) {}

    public function url(): string
    {
        $origin = rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');

        return $origin.RealmPath::for($this->realms->current()->id());
    }
}
