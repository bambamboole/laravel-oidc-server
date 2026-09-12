<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Models;

use Bambamboole\LaravelOidc\Server\Database\Factories\PasswordHistoryFactory;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $user_id
 * @property string $hash
 * @property CarbonInterface $created_at
 */
class PasswordHistory extends Model
{
    /** @use HasFactory<PasswordHistoryFactory> */
    use HasFactory;

    use HasUuids;

    protected $table = 'oidc_password_histories';

    public $timestamps = false;

    protected $guarded = [];

    protected $hidden = ['hash'];

    protected static function newFactory(): PasswordHistoryFactory
    {
        return PasswordHistoryFactory::new();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['created_at' => 'datetime'];
    }
}
