<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms;

use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\BrokeringSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\ClientSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\CredentialSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\KeySettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\LoginSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\ScopeSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\SessionSettings;
use Bambamboole\LaravelOidc\Server\Shared\Realms\Settings\TokenSettings;

/**
 * A realm is its own OpenID Provider: its identifier scopes every row the
 * package stores, and its settings drive every behavior that may differ
 * between tenants. What a realm is beyond that — name, branding,
 * administrators — belongs to the application, which implements this
 * contract on its own model and exposes it through a RealmRepository.
 */
interface Realm
{
    public function id(): string;

    public function tokens(): TokenSettings;

    public function sessions(): SessionSettings;

    public function login(): LoginSettings;

    public function credentials(): CredentialSettings;

    public function brokering(): BrokeringSettings;

    public function scopes(): ScopeSettings;

    public function clients(): ClientSettings;

    public function keys(): KeySettings;
}
