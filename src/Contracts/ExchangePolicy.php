<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Contracts;

use Bambamboole\LaravelOidc\Exchange\ExchangeGrantResult;
use Bambamboole\LaravelOidc\Exchange\ExchangeRequest;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
