<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Http\Controllers;

use Laravel\Passport\Http\Controllers\ApproveAuthorizationController as PassportApproveAuthorizationController;

class ApproveAuthorizationController extends PassportApproveAuthorizationController
{
    use RetrievesAuthRequestFromSession;
}
