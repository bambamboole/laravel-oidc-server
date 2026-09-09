<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Audit\AuditSink;
use Bambamboole\LaravelOidc\Server\Brokering\SocialUser;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentPrompt;
use Bambamboole\LaravelOidc\Server\Consents\Views\ConsentView;
use Bambamboole\LaravelOidc\Server\Keys\Jwk;
use Bambamboole\LaravelOidc\Server\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Protocol\League\EncryptionKey;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ClientEntity as BridgeClient;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\OidcAccessToken;
use Bambamboole\LaravelOidc\Server\Protocol\League\Entities\ScopeEntity;
use Bambamboole\LaravelOidc\Server\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Testing\FakeAuditSink;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\Middleware\CheckAudience;
use Bambamboole\LaravelOidc\Server\Tokens\Models\RefreshToken;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Bambamboole\LaravelOidc\Server\Users\Actions\CreateUser;
use Bambamboole\LaravelOidc\Server\Users\Actions\CreateUserFromSocialAccount;
use Bambamboole\LaravelOidc\Server\Users\Actions\ResetUserPassword;
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
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\HttpFoundation\Response;

uses(TestCase::class)
    ->in(__DIR__);
uses(RefreshDatabase::class)->in(__DIR__);

function createUsersUsing(Closure $action): void
{
    app()->bind(CreateUser::class, fn (): CreateUser => new class($action) implements CreateUser
    {
        public function __construct(private readonly Closure $action) {}

        public function __invoke(array $input): Authenticatable
        {
            return ($this->action)($input);
        }
    });
}

function resetUserPasswordsUsing(Closure $action): void
{
    app()->bind(ResetUserPassword::class, fn (): ResetUserPassword => new class($action) implements ResetUserPassword
    {
        public function __construct(private readonly Closure $action) {}

        public function __invoke(CanResetPassword $user, array $input): void
        {
            ($this->action)($user, $input);
        }
    });
}

function createUsersFromSocialUsing(Closure $action): void
{
    app()->bind(CreateUserFromSocialAccount::class, fn (): CreateUserFromSocialAccount => new class($action) implements CreateUserFromSocialAccount
    {
        public function __construct(private readonly Closure $action) {}

        public function __invoke(SocialUser $socialUser, string $provider): Authenticatable
        {
            return ($this->action)($socialUser, $provider);
        }
    });
}

/**
 * Re-runs the package's route file. Endpoints whose registration depends on
 * config (`oidc.dcr.enabled`) are bound at boot, so a test that flips the flag
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

function parseAccessToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
}

function parseIdToken(string $jwt): UnencryptedToken
{
    return parseAccessToken($jwt);
}

/**
 * Locks both halves of a rejected-flow assertion: the closure must throw an
 * OAuthServerException, and its RFC 6749 error type must match. A closure
 * that does not throw fails on the instance expectation.
 */
function expectOAuthServerError(Closure $callback, string $errorType): void
{
    $thrown = null;

    try {
        $callback();
    } catch (OAuthServerException $thrown) {
    }

    expect($thrown)->toBeInstanceOf(OAuthServerException::class)
        ->and($thrown?->getErrorType())->toBe($errorType);
}

/**
 * Mirrors League\OAuth2\Server\ResponseTypes\BearerTokenResponse::generateHttpResponse(),
 * which is how Passport actually produces refresh_token values on the wire.
 *
 * @param  array<string, mixed>  $payload
 */
function encryptRefreshTokenPayload(array $payload): string
{
    $encrypter = new class
    {
        use CryptTrait;

        public function encryptPayload(string $data): string
        {
            return $this->encrypt($data);
        }
    };

    $encrypter->setEncryptionKey(app(EncryptionKey::class)->value());

    return $encrypter->encryptPayload((string) json_encode($payload));
}

/**
 * Creates a persisted refresh-token + linked access-token pair and returns the
 * encrypted refresh token value League/Passport would hand back to a client.
 *
 * @return array{0: string, 1: RefreshToken, 2: Token}
 */
function issueRefreshToken(mixed $test, ?string $clientId = null, bool $expired = false): array
{
    $accessTokenId = Str::random(80);
    $refreshTokenId = Str::random(80);

    $accessToken = new Token;
    $accessToken->forceFill([
        'realm_id' => Token::currentRealm(),
        'id' => $accessTokenId,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    $refreshToken = new RefreshToken;
    $refreshToken->forceFill([
        'id' => $refreshTokenId,
        'access_token_id' => $accessTokenId,
        'revoked' => false,
        'expires_at' => now()->addDay(),
    ])->save();

    $encrypted = encryptRefreshTokenPayload([
        'client_id' => $clientId ?? $test->client->id,
        'refresh_token_id' => $refreshTokenId,
        'access_token_id' => $accessTokenId,
        'scopes' => ['openid'],
        'user_id' => $test->user->id,
        'expire_time' => $expired ? now()->subDay()->timestamp : now()->addDay()->timestamp,
    ]);

    return [$encrypted, $refreshToken, $accessToken];
}

/**
 * Mints an RFC 9068 access token addressed to $clientId and persists a matching
 * Passport token row so TokenInspector::accessToken() resolves it.
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
    $tokenId = Str::random(80);
    $expiresAt ??= new DateTimeImmutable('+1 hour');

    $subject = new OidcAccessToken(
        $userId,
        array_map(fn (string $scope) => new ScopeEntity($scope), $scopeIds),
        new BridgeClient($clientId, 'RP', ['https://rp.test/cb']),
    );
    $subject->setIdentifier($tokenId);
    $subject->setAudience($clientId);
    $subject->setExpiryDateTime($expiresAt);
    $subject->setPrivateKey(new CryptKey(__DIR__.'/fixtures/oauth-private.key', null, false));

    (new Token)->forceFill([
        'realm_id' => Token::currentRealm(),
        'id' => $tokenId,
        'user_id' => $userless ? null : $userId,
        'client_id' => $clientId,
        'scopes' => $scopeIds,
        'revoked' => $revoked,
        'expires_at' => $expiresAt,
    ])->save();

    return $subject->toString();
}

/**
 * Mints an RFC 9068 at+jwt access token addressed to the given resource audiences only (no client
 * id prepended) and persists a matching Passport token row. CheckAudience is now a self-contained
 * resource-server validator, so this exercises the auth:api-free path: the aud claim need not carry
 * a client id, and revocation/expiry are read from the persisted row.
 *
 * @param  string[]  $audience
 */
function resourceServerBearer(
    mixed $test,
    array $audience,
    bool $revoked = false,
    bool $expired = false,
    ?string $subjectId = null,
): string {
    $tokenId = Str::random(80);
    $expiresAt = $expired ? new DateTimeImmutable('-1 hour') : new DateTimeImmutable('+1 hour');
    $clientId = (string) $test->client->id;
    $subjectId ??= (string) $test->user->id;

    $accessToken = new OidcAccessToken(
        $subjectId,
        [new ScopeEntity('openid')],
        new BridgeClient($clientId, 'RP', ['https://rp.test/cb']),
    );
    $accessToken->setIdentifier($tokenId);
    $accessToken->setAudience(...$audience);
    $accessToken->setExpiryDateTime($expiresAt);
    $accessToken->setPrivateKey(new CryptKey(__DIR__.'/fixtures/oauth-private.key', null, false));

    (new Token)->forceFill([
        'realm_id' => Token::currentRealm(),
        'id' => $tokenId,
        'user_id' => $subjectId,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => $revoked,
        'expires_at' => $expiresAt,
    ])->save();

    return $accessToken->toString();
}

/**
 * Mints a plain JWT (default header typ=JWT, as an id_token would carry) and persists a
 * matching Passport token row. CheckAudience validates the signature and persisted row but
 * still rejects it on its typ guard, since the header typ is not at+jwt.
 */
/**
 * Binds the consent view to a closure receiving the same parameter bag the
 * authorize controller hands the view seam.
 */
function fakeConsentViewUsing(Closure $callback): void
{
    app()->instance(ConsentView::class, new class($callback) implements ConsentView
    {
        public function __construct(private readonly Closure $callback) {}

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

    (new Token)->forceFill([
        'realm_id' => Token::currentRealm(),
        'id' => $tokenId,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    return $jwt;
}
