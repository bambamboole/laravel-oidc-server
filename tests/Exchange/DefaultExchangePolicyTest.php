<?php
declare(strict_types=1);

use Bambamboole\LaravelOidc\Exchange\DefaultExchangePolicy;
use Bambamboole\LaravelOidc\Exchange\ExchangeRequest;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use League\OAuth2\Server\Exception\OAuthServerException;

/** @param  string[]  $audiences */
function exchangeClient(array $audiences = ['https://api.internal/orders']): Client
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
function subjectClaims(string $clientId, array $aud, array $scopes): array
{
    return ['sub' => '42', 'aud' => $aud, 'scope' => implode(' ', $scopes), 'client_id' => $clientId];
}

it('authorizes a reciprocal, allowlisted, narrowed exchange', function () {
    $client = exchangeClient();
    $request = new ExchangeRequest(
        $client,
        subjectClaims((string) $client->id, [(string) $client->id], ['openid', 'email', 'orders:read']),
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

it('rejects a subject token with an empty sub claim with invalid_grant', function () {
    $client = exchangeClient();
    $claims = subjectClaims((string) $client->id, [(string) $client->id], ['openid']);
    unset($claims['sub']);
    $request = new ExchangeRequest($client, $claims, 'https://api.internal/orders', null, time() + 3600);

    try {
        (new DefaultExchangePolicy)->authorize($request);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_grant');
    }
});

it('rejects when the requesting client is not in the subject token audience (reciprocity)', function () {
    $client = exchangeClient();
    $request = new ExchangeRequest($client, subjectClaims('someone-else', ['other-service'], ['openid']), 'https://api.internal/orders', null, time() + 3600);

    (new DefaultExchangePolicy)->authorize($request);
})->throws(OAuthServerException::class);

it('rejects an unlisted target audience with invalid_target', function () {
    $client = exchangeClient(['https://api.internal/orders']);
    $request = new ExchangeRequest($client, subjectClaims((string) $client->id, [(string) $client->id], ['openid']), 'https://evil/api', null, time() + 3600);

    try {
        (new DefaultExchangePolicy)->authorize($request);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_target');
    }
});

it('rejects scope widening with invalid_scope', function () {
    $client = exchangeClient();
    $request = new ExchangeRequest($client, subjectClaims((string) $client->id, [(string) $client->id], ['openid']), 'https://api.internal/orders', ['admin'], time() + 3600);

    try {
        (new DefaultExchangePolicy)->authorize($request);
        $this->fail('expected rejection');
    } catch (OAuthServerException $e) {
        expect($e->getErrorType())->toBe('invalid_scope');
    }
});

it('defaults issued scopes to the subject scopes when none requested', function () {
    $client = exchangeClient();
    $request = new ExchangeRequest($client, subjectClaims((string) $client->id, [(string) $client->id], ['openid', 'email']), 'https://api.internal/orders', null, time() + 3600);

    expect((new DefaultExchangePolicy)->authorize($request)->scopes)->toBe(['openid', 'email']);
});
