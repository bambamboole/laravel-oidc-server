<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realm;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use Symfony\Component\HttpFoundation\Response;

/**
 * Binds the matched realm to URL generation, to the session cookie and to the
 * request, then drops `{realm}` from the route parameters.
 *
 * Dropping it is what keeps controller signatures unchanged: Laravel hands
 * route parameters to a controller method positionally, so leaving a leading
 * `{realm}` in place would shift every other argument along by one.
 *
 * Runs ahead of StartSession so the cookie is written with a realm-scoped
 * path; without it every realm shares one cookie and a login in one realm is
 * a login in all of them.
 */
final readonly class ResolveRealm
{
    public const string ATTRIBUTE = 'oidc.realm';

    public function __construct(private RealmResolver $realms) {}

    public function handle(Request $request, Closure $next): Response
    {
        $realm = $this->realms->current();

        $request->attributes->set(self::ATTRIBUTE, $realm);
        $request->route()?->forgetParameter('realm');

        URL::defaults(['realm' => $realm]);
        config(['session.path' => RealmPath::for($realm)]);

        return $next($request);
    }
}
