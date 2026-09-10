<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Credentials\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface FactorSetupView
{
    public function respond(FactorSetupPrompt $prompt, Request $request): Responsable|Response;
}
