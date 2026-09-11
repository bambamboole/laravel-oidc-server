<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Keyed by user rather than by email: an address is only unique within a
 * realm, so one realm's reset request would otherwise replace another's
 * pending link.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_password_reset_tokens', function (Blueprint $table): void {
            $table->uuid('user_id')->primary();
            $table->string('realm_id')->index();
            $table->string('token');
            $table->timestamp('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_password_reset_tokens');
    }
};
