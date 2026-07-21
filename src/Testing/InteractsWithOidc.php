<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Testing;

use Bambamboole\LaravelOidc\Auth\AuthenticationMethods;
use Bambamboole\LaravelOidc\Token\AccessTokenMinter;
use DateInterval;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Assert;
use Symfony\Component\HttpFoundation\Response;

/**
 * Test helpers for consumers of the package. Add to your Pest suite with
 * `uses(InteractsWithOidc::class)` (or `use` it in a PHPUnit TestCase).
 *
 * The host class must be a Laravel HTTP test case (Illuminate's
 * `Illuminate\Foundation\Testing\TestCase` or Orchestra Testbench's) — the
 * abstract method declarations below pin exactly what the trait needs.
 */
trait InteractsWithOidc
{
    private ?Client $oidcDefaultClient = null;

    /**
     * @return static
     */
    abstract public function actingAs(Authenticatable $user, $guard = null);

    /**
     * @param  array<string, mixed>  $data
     * @return static
     */
    abstract public function withSession(array $data);

    /**
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    abstract public function get($uri, array $headers = []);

    /**
     * @param  array<string, mixed>  $data
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    abstract public function post($uri, array $data = [], array $headers = []);

    /**
     * @param  string|array<int, string>|null  $middleware
     * @return static
     */
    abstract public function withoutMiddleware($middleware = null);

    /**
     * Authenticate on the identity guard and seed the session keys the
     * authorization grant reads: `oidc.auth_time`, `oidc.amr`,
     * `oidc.id_token_claims`, `oidc.access_token_claims`.
     *
     * `acr` is intentionally not a parameter: the grant derives it from
     * `$amr` via {@see AuthenticationMethods::deriveAcr()}.
     *
     * @param  array<string, mixed>  $idTokenClaims
     * @param  array<string, mixed>  $accessTokenClaims
     * @param  list<string>  $amr
     */
    public function actingAsIdentity(
        Authenticatable $user,
        array $idTokenClaims = [],
        array $accessTokenClaims = [],
        array $amr = [],
        ?int $authTime = null,
        ?string $guard = null,
    ): static {
        $this->actingAs($user, $guard ?? (string) config('oidc.auth.guard', 'identity'));

        $session = ['oidc.auth_time' => $authTime ?? time()];

        if ($amr !== []) {
            $session[AuthenticationMethods::SESSION_KEY] = $amr;
        }

        if ($idTokenClaims !== []) {
            $session['oidc.id_token_claims'] = $idTokenClaims;
        }

        if ($accessTokenClaims !== []) {
            $session['oidc.access_token_claims'] = $accessTokenClaims;
        }

        $this->withSession($session);

        return $this;
    }

    /**
     * @param  string[]  $redirectUris
     */
    public function createOidcClient(
        string $name = 'Test Client',
        array $redirectUris = ['https://rp.test/callback'],
        bool $confidential = true,
    ): Client {
        return app(ClientRepository::class)->createAuthorizationCodeGrantClient($name, $redirectUris, $confidential);
    }

    /**
     * Create (or adopt) a client and point `oidc.first_party.*` config at it.
     */
    public function withFirstPartyClient(?Client $client = null): Client
    {
        $client ??= $this->createOidcClient('First-Party App', ['https://app.test/callback']);

        config([
            'oidc.first_party.client_id' => (string) $client->getKey(),
            'oidc.first_party.trusted' => true,
        ]);

        return $client;
    }

    public function pkce(): PkcePair
    {
        return PkcePair::generate();
    }

    /**
     * Mint a real signed access token (with a persisted Passport token row)
     * without driving the HTTP authorization flow. Creates and memoizes a
     * default client when none is given.
     *
     * @param  string[]  $scopes
     * @param  string[]  $audience
     */
    public function issueTokenFor(
        Authenticatable $user,
        ?Client $client = null,
        array $scopes = ['openid'],
        array $audience = [],
        ?DateInterval $ttl = null,
    ): string {
        $client ??= $this->oidcDefaultClient ??= $this->createOidcClient();

        return app(AccessTokenMinter::class)->mint(
            (string) $user->getAuthIdentifier(),
            $client,
            $scopes,
            $ttl ?? new DateInterval('PT1H'),
            $audience,
        )->toString();
    }

    /**
     * Drive the full authorization-code round-trip: authorize (with PKCE),
     * approve, and exchange the code at the token endpoint. The authorize and
     * approve legs assert; the token response is returned as-is so error
     * paths can be tested.
     *
     * URLs come from the named routes (`oidc.authorize`, `oidc.approve`,
     * `oidc.token`) so configured path overrides are honored. A minimal JSON
     * authorization view is registered unless the test already registered one
     * via `Passport::authorizationView()`.
     *
     * Note: the CSRF middleware exemption applied here persists for the
     * remainder of the calling test method (`withoutMiddleware()` has no
     * revert scope).
     *
     * @param  array<string, mixed>  $params  overrides for the authorize query (state, nonce, max_age, redirect_uri, ...)
     */
    public function authorizeAndApprove(
        Authenticatable $user,
        ?Client $client = null,
        string $scopes = 'openid',
        array $params = [],
        ?PkcePair $pkce = null,
    ): AuthorizationCodeResult {
        $client ??= $this->oidcDefaultClient ??= $this->createOidcClient();
        $pkce ??= PkcePair::generate();

        if (! app()->bound(AuthorizationViewResponse::class)) {
            Passport::authorizationView(
                fn (array $parameters) => response()->json(['authToken' => $parameters['authToken']]),
            );
        }

        // The `web` group binds PreventRequestForgery on Laravel 13+ but
        // ValidateCsrfToken on older versions — both must be exempted.
        $this->withoutMiddleware([ValidateCsrfToken::class, PreventRequestForgery::class]);

        $guard = (string) config('oidc.auth.guard', 'identity');

        if (! Auth::guard($guard)->check()) {
            $this->actingAsIdentity($user, guard: $guard);
        }

        $query = array_merge([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => $client->redirect_uris[0] ?? 'https://rp.test/callback',
            'response_type' => 'code',
            'scope' => $scopes,
            'state' => Str::random(16),
            'nonce' => Str::random(16),
            'code_challenge' => $pkce->challenge,
            'code_challenge_method' => 'S256',
        ], $params);

        $authorize = $this->get(route('oidc.authorize').'?'.http_build_query($query));

        // Trusted clients and already-granted scopes skip consent entirely.
        if ($authorize->isRedirect()) {
            $approve = $authorize;
        } else {
            $authorize->assertOk();

            // json() would throw on a non-JSON view before the failure below can fire.
            $decoded = json_decode((string) $authorize->getContent(), true);
            $authToken = is_array($decoded) ? ($decoded['authToken'] ?? null) : null;

            if (! is_string($authToken) || $authToken === '') {
                Assert::fail('The authorization view did not return an authToken. If your app binds a custom authorization view, register a JSON view for this test via Passport::authorizationView() before calling authorizeAndApprove().');
            }

            $approve = $this->post(route('oidc.approve'), ['auth_token' => $authToken]);
            $approve->assertRedirect();
        }

        parse_str((string) parse_url((string) $approve->headers->get('Location'), PHP_URL_QUERY), $callback);

        if (! isset($callback['code'])) {
            Assert::fail('Authorization did not yield a code. Redirected to: '.$approve->headers->get('Location'));
        }

        $tokenRequest = [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => $query['redirect_uri'],
            'code' => $callback['code'],
            'code_verifier' => $pkce->verifier,
        ];

        if ($client->plainSecret !== null) {
            $tokenRequest['client_secret'] = $client->plainSecret;
        }

        return AuthorizationCodeResult::fromResponse($this->post(route('oidc.token'), $tokenRequest));
    }
}
