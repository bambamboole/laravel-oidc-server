<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Contracts\ScopeCatalog;
use Bambamboole\LaravelOidc\Contracts\ScopeRepository;
use Bambamboole\LaravelOidc\Support\PassportConfigurator;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;

class ConfiguratorTestToken extends Token {}

class ConfiguratorTestCatalog implements ScopeCatalog
{
    public function scopes(): array
    {
        return ['thing:read' => 'Read things'];
    }
}

class ConfiguratorThrowingCatalog implements ScopeCatalog
{
    public function scopes(): array
    {
        throw new RuntimeException('no database yet');
    }
}

class ConfiguratorCountingCatalog implements ScopeCatalog
{
    public static int $calls = 0;

    public function scopes(): array
    {
        static::$calls++;

        return ['counted:scope' => 'Counted'];
    }
}

afterEach(function () {
    Passport::tokensCan([]);
    Passport::useTokenModel(Token::class);
});

it('registers an inline scope map with passport', function () {
    config()->set('oidc.passport.scopes', ['a:b' => 'desc']);

    app(PassportConfigurator::class)();

    expect(Passport::scopeIds())->toBe(['a:b']);
});

it('resolves a ScopeCatalog class-string from the container', function () {
    config()->set('oidc.passport.scopes', ConfiguratorTestCatalog::class);

    app(PassportConfigurator::class)();
    app(ScopeRepository::class);

    expect(Passport::scopeIds())->toBe(['thing:read']);
});

it('rejects a scope catalog class that does not implement the contract', function () {
    config()->set('oidc.passport.scopes', stdClass::class);

    app(PassportConfigurator::class)();
    app(ScopeRepository::class);
})->throws(LogicException::class);

it('leaves scopes empty when the catalog throws', function () {
    config()->set('oidc.passport.scopes', ConfiguratorThrowingCatalog::class);

    app(PassportConfigurator::class)();
    app(ScopeRepository::class);

    expect(Passport::scopeIds())->toBe([]);
});

it('does not materialize a catalog class until scopes are enumerated', function () {
    ConfiguratorCountingCatalog::$calls = 0;
    config()->set('oidc.passport.scopes', ConfiguratorCountingCatalog::class);

    app(PassportConfigurator::class)();

    expect(ConfiguratorCountingCatalog::$calls)->toBe(0)
        ->and(Passport::scopeIds())->toBe([]);

    app(ScopeRepository::class);

    expect(ConfiguratorCountingCatalog::$calls)->toBe(1)
        ->and(Passport::scopeIds())->toBe(['counted:scope']);
});

it('registers a configured token model', function () {
    config()->set('oidc.passport.token_model', ConfiguratorTestToken::class);

    app(PassportConfigurator::class)();

    expect(Passport::tokenModel())->toBe(ConfiguratorTestToken::class);
});

it('ignores an explicit null scopes config', function () {
    config()->set('oidc.passport.scopes', null);

    app(PassportConfigurator::class)();

    expect(Passport::scopeIds())->toBe([]);
});
