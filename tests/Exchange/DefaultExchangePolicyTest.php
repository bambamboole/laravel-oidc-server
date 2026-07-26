<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Exchange\DefaultExchangePolicy;
use Bambamboole\LaravelOidc\Server\Exchange\ExchangeRequest;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use League\OAuth2\Server\Exception\OAuthServerException;

/** @param  string[]  $audiences */
function exchangePolicyClient(array $audiences = ['https://api.internal/orders']): Client
{
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/cb']);
    $client->forceFill(['allowed_exchange_audiences' => json_encode($audiences)])->save();

    return $client;
}

/**
 * @param  string[]  $aud
 * @param  string[]  $scopes
 * @return array<string, mixed>
 */
function exchangePolicySubjectClaims(string $clientId, array $aud, array $scopes): array
{
    return ['sub' => '42', 'aud' => $aud, 'scope' => implode(' ', $scopes), 'client_id' => $clientId];
}

it('authorizes a reciprocal, allowlisted, narrowed exchange', function () {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest(
        $client,
        exchangePolicySubjectClaims((string) $client->id, [(string) $client->id], ['openid', 'email', 'orders:read']),
        'https://api.internal/orders',
        ['orders:read'],
        time() + 3600,
    );

    $result = (new DefaultExchangePolicy)->authorize($request);

    expect($result->userId)->toBe('42')
        ->and($result->scopes)->toBe(['orders:read'])
        ->and($result->audience)->toBe(['https://api.internal/orders'])
        ->and($result->expiresAt)->toBeLessThanOrEqual(time() + 3600);
});

it('rejects a policy violation with the matching OAuth error type', function (
    bool $withSub,
    string $audience,
    ?array $requestedScopes,
    string $errorType,
) {
    $client = exchangePolicyClient();
    $claims = exchangePolicySubjectClaims((string) $client->id, [(string) $client->id], ['openid']);

    if (! $withSub) {
        unset($claims['sub']);
    }

    $request = new ExchangeRequest($client, $claims, $audience, $requestedScopes, time() + 3600);

    expectOAuthServerError(fn () => (new DefaultExchangePolicy)->authorize($request), $errorType);
})->with([
    'missing sub claim' => [false, 'https://api.internal/orders', null, 'invalid_grant'],
    'unlisted target audience' => [true, 'https://evil/api', null, 'invalid_target'],
    'scope widening' => [true, 'https://api.internal/orders', ['admin'], 'invalid_scope'],
]);

it('rejects when the requesting client is not in the subject token audience (reciprocity)', function () {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest($client, exchangePolicySubjectClaims('someone-else', ['other-service'], ['openid']), 'https://api.internal/orders', null, time() + 3600);

    (new DefaultExchangePolicy)->authorize($request);
})->throws(OAuthServerException::class);

it('defaults issued scopes to the subject scopes when none requested', function () {
    $client = exchangePolicyClient();
    $request = new ExchangeRequest($client, exchangePolicySubjectClaims((string) $client->id, [(string) $client->id], ['openid', 'email']), 'https://api.internal/orders', null, time() + 3600);

    expect((new DefaultExchangePolicy)->authorize($request)->scopes)->toBe(['openid', 'email']);
});
