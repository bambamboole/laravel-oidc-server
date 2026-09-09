<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Authentication;

use Bambamboole\LaravelOidc\Server\Shared\Realms\RealmResolver;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;

final class LoginDestination
{
    public function __construct(private readonly RealmResolver $realms) {}

    public function url(): string
    {
        $destination = $this->realms->current()->login()->loginRoute;

        return Route::has($destination)
            ? route($destination)
            : URL::to($destination);
    }
}
