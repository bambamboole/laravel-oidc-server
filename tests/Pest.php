<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentPrompt;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Shared\Audit\AuditSink;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\CreateUserFromSocialAccount;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\Jwk;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Shared\SigningKeys\SigningKeyStore;
use Bambamboole\LaravelOidc\Server\Shared\Tokens\AccessTokenMinter;
use Bambamboole\LaravelOidc\Server\Shared\Users\CreateUser;
use Bambamboole\LaravelOidc\Server\Shared\Users\ResetUserPassword;
use Bambamboole\LaravelOidc\Server\SigningKeys\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Testing\FakeAuditSink;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Exceptions\ExchangeDeniedException;
use Bambamboole\LaravelOidc\Server\Tokens\Models\AccessToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Symfony\Component\HttpFoundation\Response;

uses(TestCase::class)
    ->in(__DIR__);
uses(RefreshDatabase::class)->in(__DIR__);

function createUsersUsing(Closure $action): void
{
    app()->bind(CreateUser::class, fn (): CreateUser => new readonly class($action) implements CreateUser
    {
        public function __construct(private Closure $action) {}

        public function __invoke(array $input): Authenticatable
        {
            return ($this->action)($input);
        }
    });
}

function resetUserPasswordsUsing(Closure $action): void
{
    app()->bind(ResetUserPassword::class, fn (): ResetUserPassword => new readonly class($action) implements ResetUserPassword
    {
        public function __construct(private Closure $action) {}

        public function __invoke(CanResetPassword $user, array $input): void
        {
            ($this->action)($user, $input);
        }
    });
}

function createUsersFromSocialUsing(Closure $action): void
{
    app()->bind(CreateUserFromSocialAccount::class, fn (): CreateUserFromSocialAccount => new readonly class($action) implements CreateUserFromSocialAccount
    {
        public function __construct(private Closure $action) {}

        public function __invoke(SocialUser $socialUser, string $provider): Authenticatable
        {
            return ($this->action)($socialUser, $provider);
        }
    });
}

/**
 * Re-runs the package's route file. Endpoints whose registration depends on
 * config (`oidc.clients.registration.enabled`) are bound at boot, so a test that flips the flag
 * afterwards has to rebuild the table to see the change.
 */
function reloadOidcRoutes(): void
{
    require dirname(__DIR__).'/routes/oidc.php';

    Route::getRoutes()->refreshNameLookups();
}

/**
 * Per-run root for filesystem fixtures. Everything created through this helper
 * lands under one pid-scoped directory that the shutdown hook below removes.
 */
function temporaryTestDirectory(string $prefix): string
{
    $directory = sys_get_temp_dir().'/laravel-oidc-server-tests-'.getmypid().'/'.$prefix.'-'.uniqid();
    mkdir($directory, 0755, true);

    return $directory;
}

// Plain PHP only: the Laravel app (and its facades) may already be torn down
// by the time the shutdown hook runs.
register_shutdown_function(function (): void {
    $delete = function (string $path) use (&$delete): void {
        if (! is_dir($path) || is_link($path)) {
            return;
        }

        foreach (array_diff(scandir($path) ?: [], ['.', '..']) as $entry) {
            $child = $path.'/'.$entry;
            is_dir($child) && ! is_link($child) ? $delete($child) : unlink($child);
        }

        rmdir($path);
    };

    $delete(sys_get_temp_dir().'/laravel-oidc-server-tests-'.getmypid());

    // Only this pid's database: parallel workers name theirs by token instead.
    $database = sys_get_temp_dir().'/laravel-oidc-package-tests/database-'.getmypid().'.sqlite';

    if (is_file($database)) {
        unlink($database);
    }
});

function fakeAudit(): FakeAuditSink
{
    $sink = new FakeAuditSink;
    app()->instance(AuditSink::class, $sink);

    return $sink;
}

/** Parses any JWS the package issues (access, id or logout token) without validating it. */
function parseAccessToken(string $jwt): UnencryptedToken
{
    $token = new Parser(new JoseEncoder)->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

function parseIdToken(string $jwt): UnencryptedToken
{
    return parseAccessToken($jwt);
}

function expectExchangeDenied(Closure $callback, string $error): void
{
    $thrown = null;

    try {
        $callback();
    } catch (ExchangeDeniedException $thrown) {
    }

    expect($thrown)->toBeInstanceOf(ExchangeDeniedException::class)
        ->and($thrown?->error)->toBe($error);
}

/**
 * @return array{0: string, 1: RefreshToken, 2: AccessToken}
 */
function issueRefreshToken(mixed $test, ?string $clientId = null, bool $expired = false): array
{
    $accessTokenId = Str::random(80);
    $refreshTokenId = Str::random(80);

    $accessToken = new AccessToken;
    $accessToken->forceFill([
        'realm_id' => AccessToken::currentRealm(),
        'id' => $accessTokenId,
        'user_id' => $test->user->id,
        'client_id' => $clientId ?? $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    $refreshToken = new RefreshToken;
    $refreshToken->forceFill([
        'realm_id' => RefreshToken::currentRealm(),
        'id' => $refreshTokenId,
        'access_token_id' => $accessTokenId,
        'revoked' => false,
        'expires_at' => $expired ? now()->subDay() : now()->addDay(),
    ])->save();

    return [$refreshTokenId, $refreshToken, $accessToken];
}

/**
 * Mints an RFC 9068 access token addressed to $clientId and persists the
 * matching token row so TokenInspector::accessToken() resolves it.
 *
 * @param  string[]  $scopeIds
 */
function mintExchangeSubjectToken(
    string $clientId,
    string $userId,
    array $scopeIds,
    ?DateTimeImmutable $expiresAt = null,
    bool $revoked = false,
    bool $userless = false,
): string {
    $minted = app(AccessTokenMinter::class)->mint(
        $userless ? null : $userId,
        $clientId,
        $scopeIds,
        ttlUntil($expiresAt ?? new DateTimeImmutable('+1 hour')),
        [$clientId],
    );

    if ($revoked) {
        AccessToken::query()->whereKey($minted->jti)->update(['revoked' => true]);
    }

    return $minted->jwt;
}

/**
 * Mints an RFC 9068 at+jwt access token addressed to the given resource audiences (the realm's
 * own when none are given) and persists a matching token row. The guard is a self-contained
 * resource-server validator: revocation and expiry are read from the persisted row.
 *
 * @param  string[]  $audience
 */
function resourceServerBearer(
    mixed $test,
    array $audience = [],
    bool $revoked = false,
    bool $expired = false,
    ?string $subjectId = null,
): string {
    $minted = app(AccessTokenMinter::class)->mint(
        $subjectId ?? (string) $test->user->id,
        (string) $test->client->client_id,
        ['openid'],
        ttlUntil($expired ? new DateTimeImmutable('-1 hour') : new DateTimeImmutable('+1 hour')),
        $audience,
    );

    if ($revoked) {
        AccessToken::query()->whereKey($minted->jti)->update(['revoked' => true]);
    }

    return $minted->jwt;
}

/** A TTL that lands on the given instant; negative when it lies in the past. */
function ttlUntil(DateTimeImmutable $expiresAt): DateInterval
{
    return (new DateTimeImmutable)->diff($expiresAt);
}

function fakeConsentViewUsing(Closure $callback): void
{
    app()->instance(ConsentView::class, new readonly class($callback) implements ConsentView
    {
        public function __construct(private Closure $callback) {}

        public function respond(ConsentPrompt $prompt, Request $request): Responsable|Response
        {
            return ($this->callback)([
                'client' => $prompt->client,
                'user' => $prompt->user,
                'scopes' => $prompt->scopes,
                'authToken' => $prompt->authToken,
            ]);
        }
    });
}

function signingPublicKey(): string
{
    return app(SigningKeys::class)->signingKey()->publicKeyPem;
}

function signingPrivateKey(): string
{
    return app(SigningKeys::class)->signingKey()->privateKey();
}

/**
 * Mints a plain JWT (default header typ=JWT, as an id_token would carry) signed with the realm key
 * and persists a matching access-token row, so only the typ guard can reject it as a bearer.
 */
function persistedIdTokenAsBearer(mixed $test): string
{
    $tokenId = Str::random(80);
    $now = new DateTimeImmutable;

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText(signingPrivateKey()),
        InMemory::plainText(signingPublicKey()),
    );

    $jwt = $config->builder()
        ->withHeader('kid', Jwk::fromPem(signingPublicKey())['kid'])
        ->issuedBy(app(IssuerResolver::class)->url())
        ->identifiedBy($tokenId)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $test->user->id)
        ->permittedFor((string) $test->client->id)
        ->withClaim('scopes', ['openid'])
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    (new AccessToken)->forceFill([
        'realm_id' => AccessToken::currentRealm(),
        'id' => $tokenId,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    return $jwt;
}

/**
 * Signing keys are stored per realm; a test that enters another realm has to
 * give it a key before it can mint or verify there.
 */
function generateRealmSigningKey(): void
{
    app(SigningKeyStore::class)->rotate(app(SigningKeyGenerator::class)->generate());
}
