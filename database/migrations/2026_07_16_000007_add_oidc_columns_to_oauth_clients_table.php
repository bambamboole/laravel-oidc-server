<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    public function up(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->text('allowed_exchange_audiences')->nullable()->after('redirect_uris');
            $table->text('post_logout_redirect_uris')->nullable()->after('redirect_uris');
            $table->text('backchannel_logout_uri')->nullable()->after('post_logout_redirect_uris');
            $table->boolean('backchannel_logout_session_required')->default(false)->after('backchannel_logout_uri');
            $table->string('oidc_provisioning_key', 64)->nullable()->unique();
        });
    }

    public function down(): void
    {
        Schema::table('oauth_clients', function (Blueprint $table): void {
            $table->dropUnique(['oidc_provisioning_key']);
            $table->dropColumn([
                'oidc_provisioning_key',
                'backchannel_logout_session_required',
                'backchannel_logout_uri',
                'post_logout_redirect_uris',
                'allowed_exchange_audiences',
            ]);
        });
    }
};
