<?php
declare(strict_types=1);

namespace Workbench\App\Models;

use Bambamboole\LaravelOidc\Auth\MultiFactor\Concerns\HasAuthenticationFactors;
use Bambamboole\LaravelOidc\Auth\MultiFactor\Contracts\FactorAuthenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

class User extends Authenticatable implements FactorAuthenticatable, MustVerifyEmail, OAuthenticatable
{
    use HasApiTokens, HasAuthenticationFactors, Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['email_verified_at' => 'datetime'];
    }
}
