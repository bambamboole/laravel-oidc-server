<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Pipeline;

use Bambamboole\LaravelOidc\Contracts\DeviceRecognizer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class NullDeviceRecognizer implements DeviceRecognizer
{
    public function isKnown(Authenticatable $user, Request $request): bool
    {
        return true;
    }
}
