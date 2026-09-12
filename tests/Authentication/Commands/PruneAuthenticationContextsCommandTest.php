<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Authentication\Models\AuthenticationContext;
use Carbon\CarbonInterface;
use Workbench\App\Models\User;

function pruneTestContext(CarbonInterface $expiresAt): AuthenticationContext
{
    $userId = (string) User::factory()->create()->getKey();

    $context = new AuthenticationContext;
    $context->realm_id = AuthenticationContext::currentRealm();
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

it('prunes expired contexts and keeps live ones', function (): void {
    $live = pruneTestContext(now()->addDay());
    pruneTestContext(now()->subDay());

    $this->artisan('oidc:prune-authentication-contexts')->assertExitCode(0);

    expect(AuthenticationContext::query()->pluck('id')->all())->toBe([$live->id]);
});
