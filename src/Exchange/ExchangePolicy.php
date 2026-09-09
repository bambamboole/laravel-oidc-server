<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Exchange;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
