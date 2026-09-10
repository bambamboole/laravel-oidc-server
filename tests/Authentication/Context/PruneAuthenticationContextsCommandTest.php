<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Illuminate\Support\Carbon;

function pruneTestContext(string $userId, Carbon $expiresAt): AuthenticationContext
{
    $context = new AuthenticationContext;
    $context->user_id = $userId;
    $context->amr = ['pwd'];
    $context->acr = '1';
    $context->auth_time = time();
    $context->id_token_claims = [];
    $context->access_token_claims = [];
    $context->expires_at = $expiresAt;
    $context->created_at = now();
    $context->save();

    return $context;
}

it('prunes expired contexts and keeps live ones', function () {
    $live = pruneTestContext('1', now()->addDay());
    pruneTestContext('2', now()->subDay());

    $this->artisan('oidc:prune-authentication-contexts')->assertExitCode(0);

    expect(AuthenticationContext::query()->pluck('id')->all())->toBe([$live->id]);
});
