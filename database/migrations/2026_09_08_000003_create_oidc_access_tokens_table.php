<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_access_tokens', function (Blueprint $table): void {
            $table->char('id', 80)->primary();
            $table->foreignUuid('user_id')->nullable()->index();
            $table->foreignUuid('client_id')->index();
            $table->string('name')->nullable();
            $table->json('scopes')->nullable();
            $table->boolean('revoked')->default(false);
            $table->timestamps();
            $table->dateTime('expires_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_access_tokens');
    }
};
