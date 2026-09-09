<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsAudience;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsRequest;
use Bambamboole\LaravelOidc\Server\Scopes\Claims\ClaimsResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Workbench\App\Models\User;

/** Captures the request the package hands the resolver, and echoes it back as claims. */
final class ClaimsContextRecorder implements ClaimsResolver
{
    /** @var list<ClaimsRequest> */
    public array $seen = [];

    /** @return array<string, mixed> */
    public function resolve(ClaimsRequest $request): array
    {
        $this->seen[] = $request;

        return [
            'seen_audience' => $request->audience->value,
            'seen_client' => $request->clientId,
            'seen_scopes' => $request->scopes,
            'seen_openid' => $request->hasScope('openid'),
        ];
    }
}

function recordClaimsRequests(): ClaimsContextRecorder
{
    $recorder = new ClaimsContextRecorder;

    app()->instance(ClaimsResolver::class, $recorder);

    return $recorder;
}

/** @param  list<string>  $scopes */
function claimsContextIdToken(User $user, string $clientId, array $scopes): UnencryptedToken
{
    $parsed = (new Parser(new JoseEncoder))->parse(
        app(IdTokenBuilder::class)->build(new IdTokenRequest(
            userId: (string) $user->id,
            clientId: $clientId,
            scopes: $scopes,
            accessToken: 'access-token-jwt',
        )),
    );

    if (! $parsed instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted token.');
    }

    return $parsed;
}

it('hands the id_token builder the client, scopes and id_token audience', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $seen = recordClaimsRequests();

    $parsed = claimsContextIdToken($user, 'rp-one', ['openid', 'profile']);

    expect($seen->seen)->toHaveCount(1)
        ->and($seen->seen[0]->user->getAuthIdentifier())->toBe($user->getAuthIdentifier())
        ->and($parsed->claims()->get('seen_audience'))->toBe(ClaimsAudience::IdToken->value)
        ->and($parsed->claims()->get('seen_client'))->toBe('rp-one')
        ->and($parsed->claims()->get('seen_scopes'))->toBe(['openid', 'profile'])
        ->and($parsed->claims()->get('seen_openid'))->toBeTrue();
});

it('hands userinfo the client, scopes and userinfo audience', function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    recordClaimsRequests();

    $bearer = resourceServerBearer($this, [app(IssuerResolver::class)->url()]);

    $response = $this->getJson('/realms/default/oauth/userinfo', ['Authorization' => 'Bearer '.$bearer])->assertOk();

    expect($response->json('seen_audience'))->toBe(ClaimsAudience::Userinfo->value)
        ->and($response->json('seen_scopes'))->toBe(['openid'])
        ->and($response->json('seen_client'))->toBe((string) $this->client->id);
});

it('lets a resolver emit different claims per client', function () {
    $user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);

    app()->instance(ClaimsResolver::class, new class implements ClaimsResolver
    {
        public function resolve(ClaimsRequest $request): array
        {
            return $request->clientId === 'rp-one' ? ['tenant' => 'acme'] : [];
        }
    });

    expect(claimsContextIdToken($user, 'rp-one', ['openid'])->claims()->get('tenant'))->toBe('acme')
        ->and(claimsContextIdToken($user, 'rp-two', ['openid'])->claims()->has('tenant'))->toBeFalse();
});
