<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;

/**
 * The configured issuer supplies the origin. Below `/realms/{realm}` every
 * realm is its own OpenID Provider with its own issuer; a single-realm
 * deployment is the origin itself.
 */
final readonly class RealmIssuerResolver implements IssuerResolver
{
    public function __construct(private RealmResolver $realms) {}

    public function url(): string
    {
        $origin = rtrim((string) (config('oidc.issuer') ?: config('app.url')), '/');

        return $origin.RealmRouting::configured()->issuerPath($this->realms->current()->id());
    }
}
