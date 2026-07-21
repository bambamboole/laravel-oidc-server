<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_access_token_contexts', function (Blueprint $table): void {
            // Auto-increment surrogate PK keeps InnoDB inserts sequential (this table grows one row
            // per access-token issuance, i.e. per refresh). access_token_id is looked up via its
            // unique index; context_id is never queried by, so it carries no index. char() widths
            // match the sources: Passport access-token ids are char(80); context ids are 26-char ULIDs.
            $table->bigIncrements('id');
            $table->char('access_token_id', 80)->unique();
            $table->char('context_id', 26);
            $table->timestamp('created_at')->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_access_token_contexts');
    }
};
