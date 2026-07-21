<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_sessions', function (Blueprint $table): void {
            $table->ulid('sid')->primary();
            $table->string('user_id')->index();
            $table->timestamp('created_at')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('logout_notified_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_sessions');
    }
};
