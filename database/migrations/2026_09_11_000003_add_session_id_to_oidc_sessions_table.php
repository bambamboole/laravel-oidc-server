<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The browser session a login happened in, so ending that browser session can
 * end the OIDC session behind it without reading the session payload.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('oidc_sessions', function (Blueprint $table): void {
            $table->string('session_id')->nullable()->index()->after('user_id');
        });
    }

    public function down(): void
    {
        Schema::table('oidc_sessions', function (Blueprint $table): void {
            $table->dropIndex(['session_id']);
            $table->dropColumn('session_id');
        });
    }
};
