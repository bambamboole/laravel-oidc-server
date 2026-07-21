<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Laravel\Passport\Http\Controllers\DenyAuthorizationController as PassportDenyAuthorizationController;

class DenyAuthorizationController extends PassportDenyAuthorizationController
{
    use RetrievesAuthRequestFromSession;
}
