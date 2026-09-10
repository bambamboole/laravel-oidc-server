<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Contracts;

use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeGrantResult;
use Bambamboole\LaravelOidc\Server\Tokens\Exchange\ExchangeRequest;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
