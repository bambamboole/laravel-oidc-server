<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * A consent is per resource, not per client: the same scope name means a
 * different thing at each resource server that declares it, so one row per
 * (realm, user, client) let an approval for one resource cover every other.
 *
 * Existing rows are dropped rather than carried over. They record no resource,
 * and inventing one would grant exactly the access this migration exists to
 * stop — users approve once more instead.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::table('oidc_consents')->delete();

        Schema::table('oidc_consents', function (Blueprint $table): void {
            $table->dropUnique(['realm_id', 'user_id', 'client_id']);
            $table->string('resource')->after('client_id');
            $table->unique(['realm_id', 'user_id', 'client_id', 'resource']);
        });
    }

    public function down(): void
    {
        DB::table('oidc_consents')->delete();

        Schema::table('oidc_consents', function (Blueprint $table): void {
            $table->dropUnique(['realm_id', 'user_id', 'client_id', 'resource']);
            $table->dropColumn('resource');
            $table->unique(['realm_id', 'user_id', 'client_id']);
        });
    }
};
