<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tests\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Context\OidcContext;
use Bambamboole\LaravelOidc\Server\Shared\Realms\IssuerResolver;
use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/**
 * Records what a worker resolves, so a test can assert against the realm the
 * job was queued from rather than the one the worker booted with.
 */
class RecordResolvedRealm implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    /** @var array<string, string|null> */
    public static array $seen = [];

    public static function forget(): void
    {
        self::$seen = [];
    }

    public function handle(RealmResolver $realms, IssuerResolver $issuer): void
    {
        self::$seen = [
            'realm' => $realms->current()->id(),
            'issuer' => $issuer->url(),
            'client' => OidcContext::client(),
            'authorize_path' => route('oidc.authorize', absolute: false),
            'login_url' => route('identity.login'),
            'reset_url' => (ResetPassword::$createUrlCallback)(new class
            {
                public function getEmailForPasswordReset(): string
                {
                    return 'ada@example.com';
                }
            }, 'reset-token'),
        ];
    }
}
