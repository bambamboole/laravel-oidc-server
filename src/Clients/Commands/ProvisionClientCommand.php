<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Clients\Commands;

use Bambamboole\LaravelOidc\Server\Clients\ClientRepository;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioner;
use Bambamboole\LaravelOidc\Server\Clients\FirstPartyClientProvisioningException;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;
use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Shared\Installation\EnvironmentWriteException;
use Illuminate\Console\Command;

class ProvisionClientCommand extends Command
{
    protected $signature = 'oidc:client
        {--first-party : Provision the package-managed first-party client}
        {--personal : Provision the client personal access tokens are minted against}
        {--name= : Client display name}
        {--redirect-uri=* : Registered authorization callback URI}
        {--post-logout-redirect-uri=* : Registered post-logout redirect URI}
        {--audience=* : Allowed token-exchange audience}
        {--trusted : Skip consent for this first-party client}
        {--adopt= : Adopt the existing client with this client_id}
        {--rotate : Rotate the client secret explicitly}
        {--write-env : Write provider client ID and trusted state to .env}';

    protected $description = 'Provision the package-managed first-party or personal-access OIDC client';

    public function __construct(
        private readonly FirstPartyClientProvisioner $provisioner,
        private readonly ClientRepository $clients,
        private readonly EnvironmentFile $environment,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if ($this->option('first-party') && $this->option('personal')) {
            $this->error('The --first-party and --personal options are mutually exclusive.');

            return self::INVALID;
        }

        if ($this->option('personal')) {
            return $this->provisionPersonalAccessClient();
        }

        if (! $this->option('first-party')) {
            $this->error('One of --first-party or --personal is required.');

            return self::INVALID;
        }

        $name = $this->stringOption('name');
        $redirectUris = $this->arrayOption('redirect-uri');

        if ($this->input->isInteractive()) {
            $name ??= $this->ask('Client name');

            if ($redirectUris === []) {
                $answer = $this->ask('Redirect URIs (comma separated)');
                $redirectUris = is_string($answer) ? $this->commaSeparated($answer) : [];
            }
        }

        if ($name === null || trim($name) === '') {
            $this->error('The --name option is required when running non-interactively.');

            return self::INVALID;
        }

        if ($redirectUris === []) {
            $this->error('At least one --redirect-uri option is required when running non-interactively.');

            return self::INVALID;
        }

        try {
            $result = $this->provisioner->provision(
                name: $name,
                redirectUris: $redirectUris,
                postLogoutRedirectUris: $this->arrayOption('post-logout-redirect-uri'),
                allowedExchangeAudiences: $this->arrayOption('audience'),
                adoptClientId: $this->stringOption('adopt'),
                rotateSecret: (bool) $this->option('rotate'),
            );
        } catch (FirstPartyClientProvisioningException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $trusted = (bool) $this->option('trusted');

        $this->line('OIDC_FIRST_PARTY_CLIENT='.$result->clientId);
        $this->line('OIDC_FIRST_PARTY_TRUSTED='.($trusted ? 'true' : 'false'));

        if ($result->clientSecret !== null) {
            $this->line('OIDC_RP_CLIENT_ID='.$result->clientId);
            $this->line('OIDC_RP_CLIENT_SECRET='.$result->clientSecret);
        }

        if (! $this->option('write-env')) {
            return self::SUCCESS;
        }

        if ($this->input->isInteractive()
            && ! $this->confirm('Write OIDC_FIRST_PARTY_CLIENT and OIDC_FIRST_PARTY_TRUSTED to .env?')) {
            $this->info('Credentials were not written to .env.');

            return self::SUCCESS;
        }

        try {
            $this->environment->write($result->providerEnvVariables($trusted));
        } catch (EnvironmentWriteException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * One personal-access client per realm: personal tokens are minted against
     * the oldest one, so a second run reports it instead of creating a rival.
     */
    private function provisionPersonalAccessClient(): int
    {
        $existing = $this->clients->findPersonalAccessClient();

        if ($existing instanceof Client) {
            $this->info("Personal access client already provisioned: {$existing->client_id}");

            return self::SUCCESS;
        }

        $client = $this->clients->createPersonalAccessGrantClient($this->stringOption('name') ?? 'Personal Access Client');

        $this->info("Personal access client provisioned: {$client->client_id}");

        return self::SUCCESS;
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) ? $value : null;
    }

    /** @return string[] */
    private function arrayOption(string $name): array
    {
        $value = $this->option($name);

        return is_array($value) ? $value : [];
    }

    /** @return string[] */
    private function commaSeparated(string $value): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode(',', $value)),
            static fn (string $item): bool => $item !== '',
        ));
    }
}
