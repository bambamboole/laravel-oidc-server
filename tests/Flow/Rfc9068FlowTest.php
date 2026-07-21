<?php
declare(strict_types=1);

/**
 * RFC 9068 (JWT profile for OAuth 2.0 access tokens); RFC 6750 §2.1 (bearer usage)
 */

use Bambamboole\LaravelOidc\Testing\InteractsWithOidc;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Workbench\App\Models\User;

uses(InteractsWithOidc::class);

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    Passport::authorizationView(fn (array $p) => response()->json(['authToken' => $p['authToken']]));
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

function parseRfc9068AccessToken(string $jwt): UnencryptedToken
{
    $token = (new Parser(new JoseEncoder))->parse($jwt);

    if (! $token instanceof UnencryptedToken) {
        throw new RuntimeException('Expected an unencrypted JWT.');
    }

    return $token;
}

// RFC 9068 §2.1 (at+jwt header), §2.2 (required claims)
it('issues an RFC 9068 access token through the real flow with context-store claims', function () {
    config(['app.url' => 'https://op.test']);

    $this->actingAsIdentity($this->user, accessTokenClaims: ['tenant' => 'acme']);

    $result = $this->authorizeAndApprove($this->user, $this->client, scopes: 'openid email', params: [
        'state' => 's',
        'nonce' => 'n',
    ]);
    $result->response->assertOk();

    $at = parseRfc9068AccessToken($result->accessToken);
    expect($at->headers()->get('typ'))->toBe('at+jwt')
        ->and($at->claims()->get('iss'))->toBe('https://op.test')
        ->and($at->claims()->get('scope'))->toBe('openid email')
        ->and($at->claims()->get('scopes'))->toBe(['openid', 'email'])
        ->and($at->claims()->get('tenant'))->toBe('acme')
        ->and($at->claims()->get('client_id'))->toBe($this->client->id);
});

it('still authenticates the RFC 9068 token on an auth:api route (no guard regression)', function () {
    Passport::actingAs($this->user, ['openid']);
    $this->getJson('/oauth/userinfo')->assertOk();
});
