<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Brokering\Exceptions;

use RuntimeException;

final class SocialAccountAlreadyLinkedException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('This account is already linked to another user.');
    }
}
