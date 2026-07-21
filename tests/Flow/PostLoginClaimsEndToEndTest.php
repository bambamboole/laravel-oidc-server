<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\Pipeline\LoginApi;
use Bambamboole\LaravelOidc\Auth\Pipeline\LoginEvent;
use Bambamboole\LaravelOidc\Facades\Oidc;
use Bambamboole\LaravelOidc\Tests\TestCase;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->withoutMiddleware(ValidateCsrfToken::class);
    Passport::authorizationView(fn (array $parameters) => response()->json([
        'authToken' => $parameters['authToken'],
    ]));

    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'email_verified_at' => now(), 'password' => bcrypt('secret-password')]);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
});

/**
 * @return TestResponse<JsonResponse>
 */
function driveLoginAuthorizeToken(TestCase $test): TestResponse
{
    $test->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'secret-password',
    ])->assertRedirect();

    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    $view = $test->get('/oauth/authorize?'.http_build_query([
        'client_id' => $test->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid email',
        'state' => 'st4te',
        'nonce' => 'n0nce',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ]))->assertOk();

    $approve = $test->post('/oauth/authorize', ['auth_token' => $view->json('authToken')])->assertRedirect();
    parse_str(parse_url($approve->headers->get('Location'), PHP_URL_QUERY), $params);

    return $test->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $test->client->id,
        'client_secret' => $test->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $params['code'],
        'code_verifier' => $verifier,
    ]);
}

it('carries a real postLogin claim through to the id_token', function () {
    Oidc::postLogin(fn (LoginEvent $e, LoginApi $api) => $api->setIdTokenClaim('groups', ['admin']));

    $token = driveLoginAuthorizeToken($this)->assertOk();

    $parser = new Parser(new JoseEncoder);
    $idToken = $parser->parse($token->json('id_token'));
    assert($idToken instanceof UnencryptedToken);

    expect($idToken->claims()->get('groups'))->toBe(['admin'])
        ->and($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});

it('emits no custom claim for a claim-less login, proving no stale carryover', function () {
    $token = driveLoginAuthorizeToken($this)->assertOk();

    $parser = new Parser(new JoseEncoder);
    $idToken = $parser->parse($token->json('id_token'));
    assert($idToken instanceof UnencryptedToken);

    expect($idToken->claims()->has('groups'))->toBeFalse();
});
