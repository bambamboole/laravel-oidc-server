<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums;

/**
 * What an enrolled factor is good for. A webauthn credential signs the user in
 * on its own *and* satisfies a second-factor challenge; a TOTP secret only ever
 * does the latter.
 */
enum FactorRole: string
{
    case LoginAndSecondFactor = 'login_and_second_factor';

    case SecondFactorOnly = 'second_factor_only';
}
