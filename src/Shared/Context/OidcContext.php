<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Context;

use Illuminate\Support\Facades\Context;

/**
 * What the package publishes into Laravel's context: the realm a request was
 * resolved to, and the client that made it.
 *
 * Laravel serializes the context into every queued job's payload and restores
 * it before the job runs, so a job dispatched while serving one realm resolves
 * that same realm on the worker instead of falling back to the configured one.
 * The same values reach every log line the context processor writes.
 */
final class OidcContext
{
    public const string REALM = 'oidc.realm';

    public const string CLIENT = 'oidc.client_id';

    public static function rememberRealm(string $realm): void
    {
        Context::add(self::REALM, $realm);
    }

    public static function realm(): ?string
    {
        $realm = Context::get(self::REALM);

        return is_string($realm) && $realm !== '' ? $realm : null;
    }

    public static function rememberClient(string $clientId): void
    {
        Context::add(self::CLIENT, $clientId);
    }

    public static function client(): ?string
    {
        $clientId = Context::get(self::CLIENT);

        return is_string($clientId) && $clientId !== '' ? $clientId : null;
    }
}
