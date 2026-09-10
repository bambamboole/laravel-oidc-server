<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms\Settings;

/**
 * The interactive login methods a realm can offer. Registration and password
 * reset hang off `Password`: both end in a password the realm would not
 * otherwise accept.
 */
enum LoginMethod: string
{
    case Password = 'password';
    case Passkey = 'passkey';
    case Social = 'social';

    /**
     * @param  array<int, mixed>  $values
     * @return list<self>
     */
    public static function listFromConfig(array $values): array
    {
        return array_values(array_filter(array_map(
            fn (mixed $value): ?self => is_string($value) ? self::tryFrom($value) : null,
            $values,
        )));
    }
}
