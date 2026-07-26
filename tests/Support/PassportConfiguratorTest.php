<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Support\PassportConfigurator;
use Laravel\Passport\Passport;
use Laravel\Passport\Token;

class ConfiguratorTestToken extends Token {}

afterEach(fn () => Passport::useTokenModel(Token::class));

it('registers a configured token model', function () {
    config()->set('oidc.passport.token_model', ConfiguratorTestToken::class);

    app(PassportConfigurator::class)();

    expect(Passport::tokenModel())->toBe(ConfiguratorTestToken::class);
});

it('leaves the passport token model alone when unconfigured', function () {
    config()->set('oidc.passport.token_model', null);

    app(PassportConfigurator::class)();

    expect(Passport::tokenModel())->toBe(Token::class);
});
