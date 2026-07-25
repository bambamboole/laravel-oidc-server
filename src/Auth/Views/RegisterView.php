<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface RegisterView
{
    public function respond(RegisterPrompt $prompt, Request $request): Responsable|Response;
}
