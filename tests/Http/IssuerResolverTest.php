<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Bridge\AccessToken;
use Bambamboole\LaravelOidc\Server\Bridge\Client;
use Bambamboole\LaravelOidc\Server\ConfiguredIssuerResolver;
use Bambamboole\LaravelOidc\Server\Contracts\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Scopes\BridgeScope;
use Bambamboole\LaravelOidc\Server\Token\IdTokenBuilder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use Workbench\App\Models\User;

function rebindIssuerResolverTo(string $url): void
{
    app()->instance(IssuerResolver::class, new class($url) implements IssuerResolver
    {
        public function __construct(private readonly string $url) {}

        public function url(): string
        {
            return $this->url;
        }
    });
}

function issuerResolverTestIdToken(): UnencryptedToken
{
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $accessToken = new AccessToken(
        (string) $user->id,
        [new BridgeScope('openid')],
        new Client('client-uuid', 'RP', ['https://rp.test/callback']),
    );
    $accessToken->setIdentifier('token-id');
    $accessToken->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
    $accessToken->setPrivateKey(new CryptKey(__DIR__.'/../fixtures/oauth-private.key', null, false));

    $parsed = (new Parser(new JoseEncoder))->parse(
        app(IdTokenBuilder::class)->build($accessToken, null, null),
    );

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('resolves the configured issuer and trims a trailing slash', function () {
    config(['oidc.issuer' => 'https://id.example.com/']);

    expect(app(ConfiguredIssuerResolver::class)->url())->toBe('https://id.example.com');
});

it('falls back to the app url when no issuer is configured', function () {
    config(['oidc.issuer' => null, 'app.url' => 'https://op.test/']);

    expect(app(ConfiguredIssuerResolver::class)->url())->toBe('https://op.test');
});

it('drives the discovery document from the bound resolver', function () {
    config(['oidc.issuer' => 'https://ignored.example.com']);
    rebindIssuerResolverTo('https://rebound.example.com');

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://rebound.example.com')
        ->assertJsonPath('jwks_uri', 'https://rebound.example.com/.well-known/jwks.json');
});

it('drives protected resource metadata from the bound resolver', function () {
    config([
        'oidc.issuer' => 'https://ignored.example.com',
        'oidc.protected_resources' => ['mcp' => ['scopes' => []]],
    ]);
    rebindIssuerResolverTo('https://rebound.example.com');

    $this->getJson('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://rebound.example.com/mcp')
        ->assertJsonPath('authorization_servers', ['https://rebound.example.com']);
});

it('drives the id_token issuer from the bound resolver', function () {
    config(['oidc.issuer' => 'https://ignored.example.com']);
    rebindIssuerResolverTo('https://rebound.example.com');

    expect(issuerResolverTestIdToken()->claims()->get('iss'))->toBe('https://rebound.example.com');
});
