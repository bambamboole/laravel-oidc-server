<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Contracts;

use Bambamboole\LaravelOidc\Server\Exchange\ExchangeGrantResult;
use Bambamboole\LaravelOidc\Server\Exchange\ExchangeRequest;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
