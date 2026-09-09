<?php
declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exchange;

interface ExchangePolicy
{
    public function authorize(ExchangeRequest $request): ExchangeGrantResult;
}
