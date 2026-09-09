<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication\Pipeline;

use Bambamboole\LaravelOidc\Server\Shared\Authentication\DeviceRecognizer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class NullDeviceRecognizer implements DeviceRecognizer
{
    public function isKnown(Authenticatable $user, Request $request): bool
    {
        return true;
    }
}
