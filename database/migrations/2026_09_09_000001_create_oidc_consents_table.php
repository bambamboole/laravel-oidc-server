<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * One row per (realm, user, client): the union of every scope the user has
 * ever approved for that client. Withdrawal sets `revoked_at` rather than
 * deleting, so a later approval reuses the row.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_consents', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('realm_id')->default((string) config('oidc.realm', 'default'))->index();
            $table->uuid('user_id');
            $table->foreignUuid('client_id')->index();
            $table->json('scopes');
            $table->timestamp('granted_at');
            $table->timestamp('revoked_at')->nullable();

            $table->unique(['realm_id', 'user_id', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_consents');
    }
};
