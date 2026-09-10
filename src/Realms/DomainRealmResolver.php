<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\Realm;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmRepository;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * Derives the realm from the host the request came in on, so every realm is
 * its own origin and every endpoint keeps its canonical path. Console
 * commands and queued jobs have no host and fall back to the configured
 * realm. A host the repository does not know is a 404.
 *
 * The host comes from the request, so the application must be configured to
 * trust it (Laravel's TrustHosts and TrustProxies middleware); an untrusted
 * Host header would otherwise choose the realm.
 */
final readonly class DomainRealmResolver implements RealmResolver
{
    public function __construct(
        private RealmRepository $realms,
        private RealmResolver $fallback,
    ) {}

    public function current(): Realm
    {
        $host = request()->getHost();

        if ($host === '') {
            return $this->fallback->current();
        }

        return $this->realms->findByDomain($host) ?? throw new NotFoundHttpException("No realm is served from [{$host}].");
    }
}
