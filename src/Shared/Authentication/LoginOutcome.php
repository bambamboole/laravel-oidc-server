<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Authentication;

enum LoginOutcome
{
    case Denied;
    case MfaChallenge;
    case LoggedIn;
}
