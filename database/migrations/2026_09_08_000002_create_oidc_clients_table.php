<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * `id` is the internal key foreign keys point at; `client_id` is the identifier
 * relying parties send on the wire. Keeping them apart lets a client be renamed
 * without rewriting its tokens.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_clients', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('client_id')->unique();
            $table->nullableUuidMorphs('owner');
            $table->string('name');
            $table->string('secret')->nullable();
            $table->string('provider')->nullable();
            $table->string('token_endpoint_auth_method');
            $table->json('redirect_uris');
            $table->json('post_logout_redirect_uris')->nullable();
            $table->json('grant_types');
            $table->json('scopes')->nullable();
            $table->json('allowed_exchange_audiences')->nullable();
            $table->text('backchannel_logout_uri')->nullable();
            $table->boolean('backchannel_logout_session_required')->default(false);
            $table->boolean('consent_required')->default(true);
            $table->unsignedInteger('access_token_ttl')->nullable();
            $table->unsignedInteger('id_token_ttl')->nullable();
            $table->unsignedInteger('refresh_token_ttl')->nullable();
            $table->string('provisioning_key', 64)->nullable()->unique();
            $table->boolean('revoked')->default(false);
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_clients');
    }
};
