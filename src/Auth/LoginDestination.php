<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;

final class LoginDestination
{
    public function url(): string
    {
        $destination = (string) config('oidc.login_route', 'login');

        return Route::has($destination)
            ? route($destination)
            : URL::to($destination);
    }
}
