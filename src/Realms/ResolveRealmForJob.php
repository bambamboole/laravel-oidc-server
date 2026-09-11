<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms;

use Bambamboole\LaravelOidc\Server\Realms\Http\Middleware\ResolveRealm;
use Bambamboole\LaravelOidc\Server\Shared\Context\OidcContext;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Support\Facades\URL;

/**
 * What ResolveRealm is to a request, this is to a queued job: it states which
 * realm the process is serving before the job body runs.
 *
 * The realm comes from the context, which Laravel restored from the job's
 * payload a moment earlier — this runs after the framework's own
 * JobProcessing listener because the package boots after it. It is recorded
 * on the request the same way the middleware records it, because a worker's
 * request is not an inbound one: it is built from `app.url`, so its host
 * would otherwise name whichever realm that URL happens to point at.
 */
final readonly class ResolveRealmForJob
{
    public function __construct(private RealmResolver $realms) {}

    public function __invoke(): void
    {
        $realm = OidcContext::realm();
        $attributes = request()->attributes;

        $realm === null
            ? $attributes->remove(ResolveRealm::ATTRIBUTE)
            : $attributes->set(ResolveRealm::ATTRIBUTE, $realm);

        URL::defaults(['realm' => $this->realms->current()->identifier()]);
    }
}
