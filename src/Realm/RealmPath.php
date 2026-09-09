<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Realm;

final class RealmPath
{
    public const string SEGMENT = 'realms';

    public static function for(string $realm): string
    {
        return '/'.self::SEGMENT.'/'.$realm;
    }
}
