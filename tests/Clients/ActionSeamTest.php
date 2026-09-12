<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Clients\Actions\RegisterClient;
use Bambamboole\LaravelOidc\Server\Clients\Models\Client;

/**
 * The extension-contracts guide tells consumers to replace a domain action by
 * binding their own class over its name. Controllers type-hint the action
 * concretely, so a replacement has to be a subtype: a final action cannot have
 * one, and the binding then resolves and fails on injection rather than at
 * bind time.
 */
final readonly class RegisterClientWithApproval extends RegisterClient
{
    public function __invoke(array $metadata): Client
    {
        return parent::__invoke([...$metadata, 'client_name' => 'Approved by the host']);
    }
}

it('lets an application replace a domain action by binding over its name', function (): void {
    config(['oidc.clients.registration' => [
        'enabled' => true,
        'allowed_redirect_schemes' => [],
        'allowed_redirect_domains' => ['*'],
    ]]);
    reloadOidcRoutes();

    app()->bind(RegisterClient::class, RegisterClientWithApproval::class);

    $this->postJson('/oauth/register', ['redirect_uris' => ['https://rp.test/cb']])
        ->assertCreated()
        ->assertJsonPath('client_name', 'Approved by the host');
});
