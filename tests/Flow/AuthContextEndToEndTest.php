<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
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

it('reports amr=[pwd] and acr=1 end to end for a password-only login', function () {
    $this->post(route('identity.login.store'), [
        'email' => 'm@example.com',
        'password' => 'secret-password',
    ])->assertRedirect();

    $verifier = str_repeat('v', 64);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

    $view = $this->get('/oauth/authorize?'.http_build_query([
        'client_id' => $this->client->id,
        'redirect_uri' => 'https://rp.test/callback',
        'response_type' => 'code',
        'scope' => 'openid email',
        'state' => 'st4te',
        'nonce' => 'n0nce',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ]))->assertOk();

    $approve = $this->post('/oauth/authorize', ['auth_token' => $view->json('authToken')])->assertRedirect();
    parse_str(parse_url($approve->headers->get('Location'), PHP_URL_QUERY), $params);

    $token = $this->post('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $this->client->id,
        'client_secret' => $this->client->plainSecret,
        'redirect_uri' => 'https://rp.test/callback',
        'code' => $params['code'],
        'code_verifier' => $verifier,
    ])->assertOk();

    $parser = new Parser(new JoseEncoder);
    $idToken = $parser->parse($token->json('id_token'));
    assert($idToken instanceof UnencryptedToken);

    expect($idToken->claims()->get('amr'))->toBe(['pwd'])
        ->and($idToken->claims()->get('acr'))->toBe('1');
});
