<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms\Settings;

/**
 * How hard a realm insists on a second factor. `IfEnrolled` challenges the
 * factors a user happens to have; `Always` additionally sends a user without
 * one to enrollment before the login completes.
 */
enum MfaRequirement: string
{
    case Never = 'never';
    case IfEnrolled = 'if_enrolled';
    case Always = 'always';

    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? self::tryFrom($value) ?? self::IfEnrolled : self::IfEnrolled;
    }
}
