<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Console;

use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Clients\FirstPartyClientProvisioningException;
use Bambamboole\LaravelOidc\Contracts\EnvironmentStore;
use Bambamboole\LaravelOidc\Support\EnvironmentWriteException;
use Bambamboole\LaravelOidc\Token\SigningKeyGenerator;
use Illuminate\Console\Command;

class InstallSelfCommand extends Command
{
    protected $signature = 'oidc:install-self
        {--name= : First-party client display name (defaults to the app name)}
        {--fresh : Rotate the first-party client secret instead of adopting the configured one}
        {--force : Skip the confirmation prompt}';

    protected $description = 'Configure this app as its own OIDC provider and relying party (self-SSO)';

    public function __construct(
        private readonly FirstPartyClientProvisioner $provisioner,
        private readonly EnvironmentStore $environment,
        private readonly SigningKeyGenerator $keys,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if (! is_array(config('oidc-client'))) {
            $this->error('The relying-party package is not installed. Run `composer require bambamboole/laravel-oidc-client` first.');

            return self::FAILURE;
        }

        $appUrl = rtrim((string) config('app.url'), '/');

        if ($appUrl === '') {
            $this->error('APP_URL must be set before configuring self-SSO.');

            return self::FAILURE;
        }

        $name = $this->stringOption('name') ?? $this->defaultClientName();
        $redirectUri = $appUrl.'/login/callback';

        $configuredIssuer = config('oidc.issuer');
        $hasIssuer = is_string($configuredIssuer) && $configuredIssuer !== '';
        $issuer = $hasIssuer ? $configuredIssuer : $appUrl;

        if (! $this->option('force')
            && $this->input->isInteractive()
            && ! $this->confirm("Provision the first-party client and write self-SSO configuration to .env for {$appUrl}?")) {
            $this->info('Aborted.');

            return self::SUCCESS;
        }

        $fresh = (bool) $this->option('fresh');
        $adoptClientId = $fresh ? null : $this->configuredClientId();

        try {
            $result = $this->provisioner->provision(
                name: $name,
                redirectUris: [$redirectUri, ...$this->configuredProvisionList('redirect_uris')],
                postLogoutRedirectUris: [$appUrl, ...$this->configuredProvisionList('post_logout_redirect_uris')],
                allowedExchangeAudiences: $this->configuredProvisionList('allowed_exchange_audiences'),
                adoptClientId: $adoptClientId,
                rotateSecret: $fresh,
                existingClientSecret: $fresh ? null : $this->environment->value('OIDC_RP_CLIENT_SECRET'),
            );
        } catch (FirstPartyClientProvisioningException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $variables = [
            ...$result->providerEnvVariables(true),
            'OIDC_RP_ENABLED' => 'true',
            'OIDC_RP_ISSUER' => $issuer,
            'OIDC_RP_CLIENT_ID' => $result->clientId,
            'OIDC_RP_REDIRECT_URI' => $redirectUri,
            'OIDC_RP_POST_LOGOUT_REDIRECT_URI' => $appUrl,
        ];

        if ($result->clientSecret !== null) {
            $variables['OIDC_RP_CLIENT_SECRET'] = $result->clientSecret;
        }

        if (! $hasIssuer) {
            $variables['OIDC_ISSUER'] = $appUrl;
        }

        try {
            $this->environment->write($variables);
        } catch (EnvironmentWriteException $exception) {
            $result->rollback();
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('Self-SSO configured. First-party client: '.$result->clientId);

        if (! $this->keys->hasKeys()) {
            $this->warn('No signing keys found. Run `php artisan oidc:rotate-keys` to generate them.');
        }

        $this->warn('Restart the app (and any queue workers) so the new configuration takes effect.');

        return self::SUCCESS;
    }

    private function configuredClientId(): ?string
    {
        $clientId = $this->environment->value('OIDC_FIRST_PARTY_CLIENT')
            ?? config('oidc.first_party.client_id');

        return is_string($clientId) && $clientId !== '' ? $clientId : null;
    }

    /** @return string[] */
    private function configuredProvisionList(string $key): array
    {
        return array_values(array_filter(
            (array) config("oidc.first_party.provision.{$key}", []),
            fn (mixed $value): bool => is_string($value) && trim($value) !== '',
        ));
    }

    private function defaultClientName(): string
    {
        $appName = config('app.name');

        return is_string($appName) && $appName !== '' ? $appName : 'First-party app';
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) ? $value : null;
    }
}
