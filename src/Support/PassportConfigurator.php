<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Support;

use Laravel\Passport\Passport;

class PassportConfigurator
{
    public function __invoke(): void
    {
        $tokenModel = config('oidc.passport.token_model');

        if (is_string($tokenModel) && $tokenModel !== '') {
            Passport::useTokenModel($tokenModel);
        }
    }
}
