<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Closure;
use Illuminate\Support\Facades\Log;
use Throwable;

class AccessTokenPipeline
{
    /** @var list<Closure(ClientCredentialsEvent, AccessTokenApi): void> */
    private array $clientCredentialsTriggers = [];

    /** @var list<Closure(TokenExchangeEvent, AccessTokenApi): void> */
    private array $tokenExchangeTriggers = [];

    /** @var list<Closure(PersonalAccessTokenEvent, AccessTokenApi): void> */
    private array $personalAccessTokenTriggers = [];

    /** @var list<Closure(AuthorizationCodeEvent, AccessTokenApi): void> */
    private array $authorizationCodeTriggers = [];

    public function registerClientCredentials(Closure $trigger): void
    {
        $this->clientCredentialsTriggers[] = $trigger;
    }

    public function registerTokenExchange(Closure $trigger): void
    {
        $this->tokenExchangeTriggers[] = $trigger;
    }

    public function registerPersonalAccessToken(Closure $trigger): void
    {
        $this->personalAccessTokenTriggers[] = $trigger;
    }

    public function registerAuthorizationCode(Closure $trigger): void
    {
        $this->authorizationCodeTriggers[] = $trigger;
    }

    public function hasPersonalAccessTokenTriggers(): bool
    {
        return $this->personalAccessTokenTriggers !== [];
    }

    public function hasAuthorizationCodeTriggers(): bool
    {
        return $this->authorizationCodeTriggers !== [];
    }

    public function runClientCredentials(ClientCredentialsEvent $event): AccessTokenApi
    {
        return $this->run($this->clientCredentialsTriggers, $event, 'clientCredentials', 'client_credentials_trigger_error');
    }

    public function runTokenExchange(TokenExchangeEvent $event): AccessTokenApi
    {
        return $this->run($this->tokenExchangeTriggers, $event, 'tokenExchange', 'token_exchange_trigger_error');
    }

    public function runPersonalAccessToken(PersonalAccessTokenEvent $event): AccessTokenApi
    {
        return $this->run($this->personalAccessTokenTriggers, $event, 'personalAccessToken', 'personal_access_trigger_error');
    }

    public function runAuthorizationCode(AuthorizationCodeEvent $event): AccessTokenApi
    {
        return $this->run($this->authorizationCodeTriggers, $event, 'authorizationCode', 'authorization_code_trigger_error');
    }

    /** @param list<Closure> $triggers */
    private function run(array $triggers, object $event, string $label, string $failureReason): AccessTokenApi
    {
        $api = new AccessTokenApi;

        foreach ($triggers as $trigger) {
            try {
                $trigger($event, $api);
            } catch (Throwable $exception) {
                Log::error("oidc: {$label} trigger threw; denying access token (fail-closed): ".$exception->getMessage(), [
                    'exception' => $exception,
                ]);
                $api->deny($failureReason);

                return $api;
            }

            if ($api->isDenied()) {
                return $api;
            }
        }

        return $api;
    }
}
