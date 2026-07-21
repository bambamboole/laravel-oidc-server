<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_authentication_contexts', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->string('user_id')->index();
            $table->ulid('sid')->nullable()->index();
            $table->json('amr');
            $table->string('acr')->nullable();
            $table->unsignedInteger('auth_time')->nullable();
            $table->json('id_token_claims');
            $table->json('access_token_claims');
            $table->timestamp('created_at')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_authentication_contexts');
    }
};
