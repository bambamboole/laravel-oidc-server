<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_auth_codes', function (Blueprint $table): void {
            $table->char('id', 80)->primary();
            $table->foreignUuid('user_id')->index();
            $table->foreignUuid('client_id')->index();
            $table->json('scopes')->nullable();
            $table->string('redirect_uri', 2048)->nullable();
            $table->string('code_challenge', 128);
            $table->string('code_challenge_method', 8);
            $table->string('nonce')->nullable();
            $table->unsignedBigInteger('auth_time')->nullable();
            $table->uuid('context_id')->nullable();
            $table->boolean('revoked')->default(false);
            $table->dateTime('expires_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_auth_codes');
    }
};
