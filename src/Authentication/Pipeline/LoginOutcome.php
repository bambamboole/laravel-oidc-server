<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Pipeline;

enum LoginOutcome
{
    case Denied;
    case MfaChallenge;
    case LoggedIn;
}
