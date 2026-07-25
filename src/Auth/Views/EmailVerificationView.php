<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Auth\Views;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

interface EmailVerificationView
{
    public function respond(EmailVerificationPrompt $prompt, Request $request): Responsable|Response;
}
