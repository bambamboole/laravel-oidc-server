<?php

declare(strict_types=1);

/**
 * OpenID Connect Discovery 1.0 §3 + RFC 8414 §2 (authorization server metadata)
 */
it('serves a spec-compliant discovery document', function () {
    config(['app.url' => 'https://op.test', 'oidc.issuer' => null]);

    $response = $this->getJson('/realms/default/.well-known/openid-configuration')
        ->assertOk()
        ->assertHeader('Cache-Control', 'max-age=3600, public');

    $response->assertJson([
        'issuer' => 'https://op.test/realms/default',
        'response_types_supported' => ['code'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['S256'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
    ]);

    expect($response->json('authorization_endpoint'))->toContain('/realms/default/oauth/authorize')
        ->and($response->json('token_endpoint'))->toContain('/realms/default/oauth/token')
        ->and($response->json('jwks_uri'))->toContain('/realms/default/.well-known/jwks.json')
        ->and($response->json('scopes_supported'))->toContain('openid', 'profile', 'email')
        ->and($response->json('grant_types_supported'))->toContain('authorization_code', 'refresh_token');
});

it('honours a configured issuer and strips trailing slashes', function () {
    config(['oidc.issuer' => 'https://id.example.com/']);

    $this->getJson('/realms/default/.well-known/openid-configuration')
        ->assertJsonPath('issuer', 'https://id.example.com/realms/default');
});

it('advertises the OAuth 2.1 / RFC 8414 / RFC 9207 metadata fields', function () {
    $doc = $this->getJson('/realms/default/.well-known/openid-configuration')->assertOk();

    expect($doc->json('grant_types_supported'))->toContain('client_credentials')
        ->and($doc->json('response_modes_supported'))->toBe(['query'])
        ->and($doc->json('claims_parameter_supported'))->toBeFalse()
        ->and($doc->json('request_parameter_supported'))->toBeFalse()
        ->and($doc->json('request_uri_parameter_supported'))->toBeFalse()
        ->and($doc->json('authorization_response_iss_parameter_supported'))->toBeTrue()
        ->and($doc->json('introspection_endpoint_auth_methods_supported'))->toBe(['client_secret_basic', 'client_secret_post'])
        ->and($doc->json('revocation_endpoint_auth_methods_supported'))->toBe(['client_secret_basic', 'client_secret_post', 'none']);
});

// OIDC Discovery 1.0 §3 — acr_values_supported, and the session claims the id_token carries
it('advertises the realm acr values and the acr, amr and sid claims', function () {
    $doc = $this->getJson('/realms/default/.well-known/openid-configuration')->assertOk();

    expect($doc->json('acr_values_supported'))->toBe(['1', '2'])
        ->and($doc->json('claims_supported'))->toContain('acr', 'amr', 'sid');

    config(['oidc.auth.acr_values' => ['single_factor' => 'urn:example:loa:1', 'multi_factor' => 'urn:example:loa:2']]);

    expect($this->getJson('/realms/default/.well-known/openid-configuration')->json('acr_values_supported'))
        ->toBe(['urn:example:loa:1', 'urn:example:loa:2']);
});

it('advertises back-channel logout support', function () {
    $doc = $this->getJson('/realms/default/.well-known/openid-configuration')->assertOk()->json();

    expect($doc['backchannel_logout_supported'])->toBeTrue()
        ->and($doc['backchannel_logout_session_supported'])->toBeTrue();
});

it('builds endpoint URLs from the configured issuer host', function () {
    config(['oidc.issuer' => 'https://id.example.com', 'app.url' => 'https://app.internal']);

    $doc = $this->getJson('/realms/default/.well-known/openid-configuration')->assertOk();

    expect($doc->json('issuer'))->toBe('https://id.example.com/realms/default')
        ->and($doc->json('authorization_endpoint'))->toStartWith('https://id.example.com/')
        ->and($doc->json('token_endpoint'))->toStartWith('https://id.example.com/')
        ->and($doc->json('jwks_uri'))->toStartWith('https://id.example.com/')
        ->and($doc->json('userinfo_endpoint'))->toStartWith('https://id.example.com/');
});
