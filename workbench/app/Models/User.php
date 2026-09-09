<?php
declare(strict_types=1);

namespace Workbench\App\Models;

use Bambamboole\LaravelOidc\Server\Credentials\Concerns\HasAuthenticationFactors;
use Bambamboole\LaravelOidc\Server\Tokens\Concerns\HasOidcTokens;
use Bambamboole\LaravelOidc\Server\Tokens\OAuthenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passkeys\Contracts\PasskeyUser;

class User extends Authenticatable implements MustVerifyEmail, OAuthenticatable, PasskeyUser
{
    use HasAuthenticationFactors, HasOidcTokens, HasUuids, Notifiable;

    protected $table = 'users';

    protected $guarded = [];

    protected function casts(): array
    {
        return ['email_verified_at' => 'datetime'];
    }
}
