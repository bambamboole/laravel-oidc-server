<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('oidc_recovery_codes', function (Blueprint $table): void {
            $table->id();
            $table->string('authenticatable_type');
            $table->string('authenticatable_id');
            $table->text('code');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->index(['authenticatable_type', 'authenticatable_id'], 'oidc_recovery_authenticatable_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_recovery_codes');
    }
};
