<?php
declare(strict_types=1);

it('registers the oidc config', function () {
    expect(config('oidc.tokens.lifetimes.id_token'))->toBe(3600)
        ->and(config('oidc.routes'))->toBe(['middleware' => []]);
});
