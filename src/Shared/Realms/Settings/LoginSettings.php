<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms\Settings;

final readonly class LoginSettings
{
    /**
     * @param  string  $usernameField  the credential field the password login reads
     * @param  string  $home  where a signed-in user lands
     * @param  string  $loginRoute  route name or path the authorize endpoint sends anonymous users to
     * @param  string  $logoutRedirect  where end-session lands without a post_logout_redirect_uri
     */
    public function __construct(
        public string $usernameField = 'email',
        public string $home = '/dashboard',
        public string $loginRoute = 'login',
        public string $logoutRedirect = '/',
    ) {}

    public static function fromConfig(): self
    {
        return new self(
            usernameField: (string) config('oidc.auth.username', 'email'),
            home: (string) config('oidc.auth.home', '/dashboard'),
            loginRoute: (string) config('oidc.login_route', 'login'),
            logoutRedirect: (string) config('oidc.logout_redirect', '/'),
        );
    }
}
