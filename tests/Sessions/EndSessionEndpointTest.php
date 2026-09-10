<?php

declare(strict_types=1);

/**
 * OpenID Connect RP-Initiated Logout 1.0 §2 (id_token_hint, client_id, post_logout_redirect_uri, state),
 * §4 (security/CSRF), §6 (confirmation)
 */

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Sessions\LogoutConfirmation;
use Bambamboole\LaravelOidc\Server\Sessions\Views\LogoutConfirmationView;
use Bambamboole\LaravelOidc\Server\Sessions\Views\LogoutPrompt;
use Bambamboole\LaravelOidc\Server\Tests\TestCase;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenBuilder;
use Bambamboole\LaravelOidc\Server\Tokens\IdTokenRequest;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Workbench\App\Models\User;

beforeEach(function () {
    $this->user = User::create(['name' => 'M', 'email' => 'm@example.com', 'password' => 'x']);
    $this->client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('RP', ['https://rp.test/callback']);
    $this->client->forceFill(['post_logout_redirect_uris' => ['https://rp.test/logged-out']])->save();
});

function issueIdToken(TestCase $test, ?User $subject = null): string
{
    $user = $subject ?? $test->user;

    return app(IdTokenBuilder::class)->build(new IdTokenRequest(
        userId: (string) $user->id,
        clientId: (string) $test->client->id,
        scopes: ['openid'],
        accessToken: 'access-token-jwt',
    ));
}

it('logs out and redirects to a registered post_logout_redirect_uri', function () {
    $response = $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]));

    $response->assertRedirect('https://rp.test/logged-out?state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('answers an Inertia logout request with a 409 + X-Inertia-Location instead of a redirect', function () {
    $response = $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]), ['X-Inertia' => 'true']);

    $response->assertStatus(409);
    expect($response->headers->get('X-Inertia-Location'))->toBe('https://rp.test/logged-out?state=xyz');
    expect(auth('identity')->guest())->toBeTrue();
});

it('falls back to the configured redirect for unregistered uris', function () {
    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'post_logout_redirect_uri' => 'https://evil.test/phish',
    ]))->assertRedirect('/');
});

it('does not log out on a GET without a valid id_token_hint', function () {
    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => 'garbage',
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
    ]))->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});

it('does not log out on a parameterless GET', function () {
    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout')->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});

it('logs out on a POST without a valid id_token_hint', function () {
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/realms/default/oauth/logout')
        ->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('logs out on a GET with a valid id_token_hint', function () {
    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
    ]))->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('does not log out when the hint sub does not match the current user', function () {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);

    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this, $other),
    ]))->assertRedirect('/');

    expect(auth('identity')->check())->toBeTrue();
});

// §2 — client_id identifies the RP when no id_token_hint is given
it('honours a post_logout_redirect_uri registered on the client named by client_id', function () {
    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/realms/default/oauth/logout', [
            'client_id' => $this->client->client_id,
            'post_logout_redirect_uri' => 'https://rp.test/logged-out',
            'state' => 'xyz',
        ])
        ->assertRedirect('https://rp.test/logged-out?state=xyz');

    expect(auth('identity')->guest())->toBeTrue();
});

it('falls back to the configured redirect when client_id names a client the uri is not registered on', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/realms/default/oauth/logout', [
            'client_id' => $other->client_id,
            'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        ])
        ->assertRedirect('/');

    expect(auth('identity')->guest())->toBeTrue();
});

it('sends a signed-out browser on to the uri registered on the client named by client_id', function () {
    $this->get('/realms/default/oauth/logout?'.http_build_query([
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]))->assertRedirect('https://rp.test/logged-out?state=xyz');
});

// §2 — client_id and id_token_hint must agree
it('rejects a client_id that is not in the audience of the id_token_hint', function () {
    $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other', ['https://other.test/cb']);

    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'client_id' => $other->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_request');

    expect(auth('identity')->check())->toBeTrue();
});

it('accepts a client_id matching the hint audience and ignores logout_hint and ui_locales', function () {
    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this),
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'logout_hint' => 'm@example.com',
        'ui_locales' => 'de-DE en',
    ]))->assertRedirect('https://rp.test/logged-out');

    expect(auth('identity')->guest())->toBeTrue();
});

function bindLogoutConfirmationView(): void
{
    app()->instance(LogoutConfirmationView::class, new class implements LogoutConfirmationView
    {
        public function respond(LogoutPrompt $prompt, Request $request): JsonResponse
        {
            return response()->json([
                'user' => (string) $prompt->user->getAuthIdentifier(),
                'client' => $prompt->client?->client_id,
                'post_logout_redirect_uri' => $prompt->postLogoutRedirectUri,
                'state' => $prompt->state,
                'confirmation' => $prompt->confirmationToken,
            ]);
        }
    });
}

// §6 — a GET without a verifiable hint asks the signed-in user; the confirmed POST performs the logout
it('renders the confirmation view for a GET without a verifiable hint and logs out on the confirmed POST', function () {
    bindLogoutConfirmationView();

    $prompt = $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'client_id' => $this->client->client_id,
        'post_logout_redirect_uri' => 'https://rp.test/logged-out',
        'state' => 'xyz',
    ]))->assertOk();

    expect(auth('identity')->check())->toBeTrue()
        ->and($prompt->json('user'))->toBe((string) $this->user->id)
        ->and($prompt->json('client'))->toBe($this->client->client_id)
        ->and($prompt->json('post_logout_redirect_uri'))->toBe('https://rp.test/logged-out')
        ->and($prompt->json('state'))->toBe('xyz')
        ->and($prompt->json('confirmation'))->toBeString();

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->post('/realms/default/oauth/logout', ['logout_confirmation' => $prompt->json('confirmation')])
        ->assertRedirect('https://rp.test/logged-out?state=xyz');

    expect(auth('identity')->guest())->toBeTrue();
});

it('prompts the signed-in user instead of trusting a hint issued to somebody else', function () {
    bindLogoutConfirmationView();
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);

    $this->actingAs($this->user, 'identity')->get('/realms/default/oauth/logout?'.http_build_query([
        'id_token_hint' => issueIdToken($this, $other),
    ]))->assertOk()->assertJsonPath('user', (string) $this->user->id)->assertJsonPath('post_logout_redirect_uri', null);

    expect(auth('identity')->check())->toBeTrue();
});

it('rejects a confirmation issued to another user or tampered with', function () {
    $other = User::create(['name' => 'O', 'email' => 'o@example.com', 'password' => 'x']);
    $foreign = app(LogoutConfirmation::class)->issue($other, 'https://rp.test/logged-out', null);

    $this->withoutMiddleware(ValidateCsrfToken::class)->actingAs($this->user, 'identity');

    $this->post('/realms/default/oauth/logout', ['logout_confirmation' => $foreign])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');
    $this->post('/realms/default/oauth/logout', ['logout_confirmation' => 'garbage'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    expect(auth('identity')->check())->toBeTrue();
});

it('rejects an expired confirmation', function () {
    $token = app(LogoutConfirmation::class)->issue($this->user, null, null);

    $this->travel(11)->minutes();

    $this->withoutMiddleware(ValidateCsrfToken::class)
        ->actingAs($this->user, 'identity')
        ->post('/realms/default/oauth/logout', ['logout_confirmation' => $token])
        ->assertStatus(400);

    expect(auth('identity')->check())->toBeTrue();
});
