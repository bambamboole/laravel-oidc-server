<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * `realm_id` is an opaque identifier the application owns — there is no realm
 * table here and no foreign key, exactly as with `user_id`. A string rather
 * than a uuid so a host-derived slug can be stored without a lookup.
 */
return new class extends Migration
{
    private const array TABLES = [
        'oidc_clients',
        'oidc_access_tokens',
        'oidc_auth_codes',
        'oidc_sessions',
        'oidc_signing_keys',
        'oidc_authentication_contexts',
        'oidc_social_accounts',
    ];

    public function up(): void
    {
        $default = (string) config('oidc.realm', 'default');

        foreach (self::TABLES as $table) {
            Schema::table($table, function (Blueprint $blueprint) use ($default): void {
                $blueprint->string('realm_id')->default($default)->index();
            });
        }

        // A client_id only has to be unique within its realm.
        Schema::table('oidc_clients', function (Blueprint $table): void {
            $table->dropUnique(['client_id']);
        });

        Schema::table('oidc_clients', function (Blueprint $table): void {
            $table->unique(['realm_id', 'client_id']);
        });

        DB::table('oidc_clients')->whereNull('realm_id')->update(['realm_id' => $default]);
    }

    public function down(): void
    {
        Schema::table('oidc_clients', function (Blueprint $table): void {
            $table->dropUnique(['realm_id', 'client_id']);
        });

        foreach (self::TABLES as $table) {
            Schema::table($table, function (Blueprint $blueprint): void {
                $blueprint->dropColumn('realm_id');
            });
        }

        Schema::table('oidc_clients', function (Blueprint $table): void {
            $table->unique(['client_id']);
        });
    }
};
