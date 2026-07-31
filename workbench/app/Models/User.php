<?php
declare(strict_types=1);

namespace Workbench\App\Models;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Concerns\HasAuthenticationFactors;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passkeys\Contracts\PasskeyUser;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

class User extends Authenticatable implements MustVerifyEmail, OAuthenticatable, PasskeyUser
{
    use HasApiTokens, HasAuthenticationFactors, HasUuids, Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['email_verified_at' => 'datetime'];
    }
}
