<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth;

use Bambamboole\LaravelOidc\Auth\Models\AuthenticationContext;
use Illuminate\Support\Carbon;

class AuthenticationContextStore
{
    /**
     * @param  array{user_id: string, sid: ?string, amr: list<string>, acr: ?string, auth_time: ?int, id_token_claims: array<string, mixed>, access_token_claims: array<string, mixed>, expires_at: \DateTimeInterface}  $attributes
     */
    public function create(array $attributes): string
    {
        $context = new AuthenticationContext;
        $context->user_id = $attributes['user_id'];
        $context->sid = $attributes['sid'];
        $context->amr = $attributes['amr'];
        $context->acr = $attributes['acr'];
        $context->auth_time = $attributes['auth_time'];
        $context->id_token_claims = $attributes['id_token_claims'];
        $context->access_token_claims = $attributes['access_token_claims'];
        $context->expires_at = Carbon::instance($attributes['expires_at']);
        $context->created_at = now();
        $context->save();

        return $context->id;
    }

    public function find(string $id): ?AuthenticationContext
    {
        return AuthenticationContext::query()->find($id);
    }
}
