<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Realms\RealmIssuerResolver;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
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
    $parsed = (new Parser(new JoseEncoder))->parse(
        app(IdTokenBuilder::class)->build(new IdTokenRequest(
            userId: (string) $user->id,
            clientId: 'client-uuid',
            scopes: ['openid'],
            accessToken: 'access-token-jwt',
        )),
    );

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('hangs the realm off the configured issuer and trims a trailing slash', function () {
    config(['oidc.issuer' => 'https://id.example.com/']);

    expect(app(RealmIssuerResolver::class)->url())->toBe('https://id.example.com/realms/default');
});

it('falls back to the app url when no issuer is configured', function () {
    config(['oidc.issuer' => null, 'app.url' => 'https://op.test/']);

    expect(app(RealmIssuerResolver::class)->url())->toBe('https://op.test/realms/default');
});

it('drives the discovery document from the bound resolver', function () {
    config(['oidc.issuer' => 'https://ignored.example.com']);
    rebindIssuerResolverTo('https://rebound.example.com');

    $this->getJson('/realms/default/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://rebound.example.com')
        ->assertJsonPath('jwks_uri', 'https://rebound.example.com/realms/default/.well-known/jwks.json');
});

it('drives protected resource metadata from the bound resolver', function () {
    config([
        'oidc.issuer' => 'https://ignored.example.com',
        'oidc.protected_resources' => ['mcp' => ['scopes' => []]],
    ]);
    rebindIssuerResolverTo('https://rebound.example.com');

    $this->getJson('/.well-known/oauth-protected-resource/realms/default/mcp')
        ->assertOk()
        ->assertJsonPath('resource', 'https://rebound.example.com/mcp')
        ->assertJsonPath('authorization_servers', ['https://rebound.example.com']);
});

it('drives the id_token issuer from the bound resolver', function () {
    config(['oidc.issuer' => 'https://ignored.example.com']);
    rebindIssuerResolverTo('https://rebound.example.com');

    expect(issuerResolverTestIdToken()->claims()->get('iss'))->toBe('https://rebound.example.com');
});
