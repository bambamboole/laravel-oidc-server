<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Issuer;
use Bambamboole\LaravelOidc\Tests\TestCase;
use Bambamboole\LaravelOidc\Token\Jwk;
use Bambamboole\LaravelOidc\Token\OidcAccessToken;
use Bambamboole\LaravelOidc\Token\SigningKeys;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\Client as BridgeClient;
use Laravel\Passport\Bridge\Scope as BridgeScope;
use Laravel\Passport\Passport;
use Laravel\Passport\RefreshToken;
use Laravel\Passport\Token;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;

uses(TestCase::class)->in(__DIR__);
uses(RefreshDatabase::class)->in(__DIR__);

function parseAccessToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $token;
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

    $encrypter->setEncryptionKey(Passport::tokenEncryptionKey(app(EncrypterContract::class)));

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

    $accessToken = Passport::token();
    $accessToken->forceFill([
        'id' => $accessTokenId,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    $refreshToken = Passport::refreshToken();
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
        array_map(fn (string $scope) => new BridgeScope($scope), $scopeIds),
        new BridgeClient($clientId, 'RP', ['https://rp.test/cb']),
    );
    $subject->setIdentifier($tokenId);
    $subject->setAudience($clientId);
    $subject->setExpiryDateTime($expiresAt);
    $subject->setPrivateKey(new CryptKey(__DIR__.'/fixtures/oauth-private.key', null, false));

    Passport::token()->forceFill([
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
        [new BridgeScope('openid')],
        new BridgeClient($clientId, 'RP', ['https://rp.test/cb']),
    );
    $accessToken->setIdentifier($tokenId);
    $accessToken->setAudience(...$audience);
    $accessToken->setExpiryDateTime($expiresAt);
    $accessToken->setPrivateKey(new CryptKey(__DIR__.'/fixtures/oauth-private.key', null, false));

    Passport::token()->forceFill([
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
function persistedIdTokenAsBearer(mixed $test): string
{
    $tokenId = Str::random(80);
    $now = new DateTimeImmutable;

    $config = Configuration::forAsymmetricSigner(
        new Sha256,
        InMemory::plainText(SigningKeys::privateKey()),
        InMemory::plainText(SigningKeys::publicKey()),
    );

    $jwt = $config->builder()
        ->withHeader('kid', Jwk::fromPem(SigningKeys::publicKey())['kid'])
        ->issuedBy(Issuer::url())
        ->identifiedBy($tokenId)
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+1 hour'))
        ->relatedTo((string) $test->user->id)
        ->permittedFor((string) $test->client->id)
        ->withClaim('scopes', ['openid'])
        ->getToken($config->signer(), $config->signingKey())
        ->toString();

    Passport::token()->forceFill([
        'id' => $tokenId,
        'user_id' => $test->user->id,
        'client_id' => $test->client->id,
        'scopes' => ['openid'],
        'revoked' => false,
        'expires_at' => now()->addHour(),
    ])->save();

    return $jwt;
}
