<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Passport's Client model reads an optional `scopes` column (absent = the
 * client may request any scope) that its own migrations never create. Dynamic
 * client registration uses it to restrict registered clients to
 * `oidc.dcr.default_scopes`.
 */
return new class extends Migration
{
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->text('scopes')->nullable()->after('grant_types');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropColumn('scopes');
        });
    }
};
