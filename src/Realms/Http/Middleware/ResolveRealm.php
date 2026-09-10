<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realms\Http\Middleware;

use Bambamboole\LaravelOidc\Server\Realms\RealmPath;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\URL;
use LogicException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs before StartSession so provider logins cannot consume or regenerate the
 * relying party's session. Removing the realm parameter preserves controller arguments.
 */
final readonly class ResolveRealm
{
    public const string ATTRIBUTE = 'oidc.realm';

    public function __construct(private RealmResolver $realms, private Store $session) {}

    public function handle(Request $request, Closure $next): Response
    {
        $realm = $this->realms->current()->id();

        $request->attributes->set(self::ATTRIBUTE, $realm);
        $request->route()?->forgetParameter('realm');

        URL::defaults(['realm' => $realm]);
        $originalCookie = (string) config('session.cookie');
        $originalPath = config('session.path');
        $originalName = $this->session->getName();
        $path = RealmPath::for($realm);
        $cookie = $this->realms->current()->sessions()->cookieName ?? $originalCookie.'-oidc-'.str_replace('.', '_', $realm);

        if ($cookie === $originalCookie || preg_match('/\A[A-Za-z0-9_-]+\z/', $cookie) !== 1) {
            throw new LogicException('The realm session cookie must have a distinct name using letters, digits, underscores or hyphens.');
        }

        config(['session.cookie' => $cookie, 'session.path' => $path]);
        $this->session->setName($cookie);

        try {
            $response = $next($request);

            if ($request->hasSession()) {
                $response->headers->clearCookie($originalCookie, $path, config('session.domain'));
                $location = $response->headers->get('Location') ?? $response->headers->get('X-Inertia-Location');

                if (is_string($location) && ! $this->staysInRealm($request, $location, $path)) {
                    $response->headers->clearCookie('XSRF-TOKEN', $path, config('session.domain'));
                }
            }

            return $response;
        } finally {
            config(['session.cookie' => $originalCookie, 'session.path' => $originalPath]);
            $this->session->setName($originalName);
        }
    }

    private function staysInRealm(Request $request, string $location, string $path): bool
    {
        $host = parse_url($location, PHP_URL_HOST);
        $targetPath = (string) parse_url($location, PHP_URL_PATH);

        return ($host === null || $host === $request->getHost())
            && ($targetPath === $path || str_starts_with($targetPath, $path.'/'));
    }
}
