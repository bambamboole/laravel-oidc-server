<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

interface DeviceRecognizer
{
    public function isKnown(Authenticatable $user, Request $request): bool;
}
