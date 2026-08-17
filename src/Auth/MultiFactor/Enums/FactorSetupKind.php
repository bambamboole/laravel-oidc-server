<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Enums;

/**
 * How an enrollment is completed, so a setup surface can pick its body without
 * type-checking concrete providers. `Code` means the server issued a secret and
 * the user types a code back; `Ceremony` means the browser produces the proof
 * (webauthn) and the server only stores it.
 */
enum FactorSetupKind: string
{
    case Code = 'code';

    case Ceremony = 'ceremony';
}
