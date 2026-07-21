<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Support;

trait ResolvesRequestGrantType
{
    private function requestGrantType(): ?string
    {
        if (! app()->bound('request')) {
            return null;
        }

        $value = app('request')->input('grant_type');

        return is_string($value) ? $value : null;
    }
}
