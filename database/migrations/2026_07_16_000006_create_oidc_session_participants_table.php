<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_session_participants', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->ulid('sid')->index();
            $table->string('client_id');
            $table->timestamp('created_at')->nullable();
            $table->unique(['sid', 'client_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_session_participants');
    }
};
