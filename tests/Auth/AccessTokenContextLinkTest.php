<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Auth\AccessTokenContextLink;

it('stores and resolves a token→context link', function () {
    $link = app(AccessTokenContextLink::class);

    $link->link('access-token-1', 'context-abc');

    expect($link->contextIdFor('access-token-1'))->toBe('context-abc')
        ->and($link->contextIdFor('unknown'))->toBeNull();
});
