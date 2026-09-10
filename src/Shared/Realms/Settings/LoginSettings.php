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
     * @param  array{single_factor: string, multi_factor: string}  $acrValues  the `acr` (OIDC Core §2) an authentication earns with one method in `amr` and with several
     */
    public function __construct(
        public string $usernameField = 'email',
        public string $home = '/dashboard',
        public string $loginRoute = 'login',
        public string $logoutRedirect = '/',
        public array $acrValues = ['single_factor' => '1', 'multi_factor' => '2'],
    ) {}

    public static function fromConfig(): self
    {
        $acrValues = (array) config('oidc.auth.acr_values', []);

        return new self(
            usernameField: (string) config('oidc.auth.username', 'email'),
            home: (string) config('oidc.auth.home', '/dashboard'),
            loginRoute: (string) config('oidc.auth.login_route', 'login'),
            logoutRedirect: (string) config('oidc.auth.logout_redirect', '/'),
            acrValues: [
                'single_factor' => (string) ($acrValues['single_factor'] ?? '1'),
                'multi_factor' => (string) ($acrValues['multi_factor'] ?? '2'),
            ],
        );
    }
}
