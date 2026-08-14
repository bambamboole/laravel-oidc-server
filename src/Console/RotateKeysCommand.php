<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Console;

use Bambamboole\LaravelOidc\Server\Audit\AuditEventType;
use Bambamboole\LaravelOidc\Server\Audit\Auditor;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyGenerator;
use Bambamboole\LaravelOidc\Server\Token\SigningKeys;
use Bambamboole\LaravelOidc\Server\Token\SigningKeyStore;
use Illuminate\Console\Command;
use RuntimeException;
use Throwable;

class RotateKeysCommand extends Command
{
    protected $signature = 'oidc:rotate-keys
        {--print : Print the env variables instead of writing them to the key store}
        {--force : Skip the confirmation prompt}
        {--if-missing : Only generate when no signing keys exist yet (skips the confirmation prompt)}';

    protected $description = 'Generate a new OIDC signing keypair, rolling the current public key into the previous set';

    public function __construct(
        private readonly SigningKeyGenerator $keys,
        private readonly SigningKeyStore $store,
    ) {
        parent::__construct();
    }

    public function handle(): int
    {
        if ($this->option('if-missing') && $this->keys->hasKeys()) {
            $this->info('Signing keys already exist; nothing to generate.');

            return self::SUCCESS;
        }

        $current = $this->currentPublicKey();

        if (! $this->option('force')
            && ! $this->option('print')
            && ! $this->option('if-missing')
            && ! $this->confirm('Generate a new signing keypair and store it?')) {
            $this->info('Aborted.');

            return self::SUCCESS;
        }

        $generated = $this->keys->generate();

        if ($this->option('print')) {
            $vars = [
                'OIDC_PRIVATE_KEY' => $generated->privateKeyPem,
                'OIDC_PUBLIC_KEY' => $generated->publicKeyPem,
            ];

            if ($current !== null) {
                $vars['OIDC_PREVIOUS_PUBLIC_KEY'] = $current;
            }

            $this->printVars($vars);
        } else {
            try {
                $this->store->rotate($generated);
            } catch (RuntimeException $exception) {
                $this->error($exception->getMessage());

                return self::FAILURE;
            }

            app(Auditor::class)->log(AuditEventType::KeysRotated, context: [
                'kid' => $generated->kid,
            ]);
        }

        $this->info('New signing key generated. New kid: '.$generated->kid);

        if ($current !== null) {
            $this->line('The previous public key stays in JWKS via the key store. Remove it once every token signed by it has expired.');
        }

        if (! $this->option('print')) {
            $this->warn('Restart the app (and any queue workers) so the new keys take effect.');
        }

        return self::SUCCESS;
    }

    private function currentPublicKey(): ?string
    {
        try {
            return SigningKeys::publicKey();
        } catch (Throwable) {
            return null;
        }
    }

    /** @param array<string, string> $vars */
    private function printVars(array $vars): void
    {
        $this->warn('Add these to your environment (the private key is secret — never commit it):');

        foreach ($vars as $name => $pem) {
            $this->line($name.'='.EnvironmentFile::encode($pem));
        }
    }
}
