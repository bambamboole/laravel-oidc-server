<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Brokering\Actions\LinkSocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\Actions\UnlinkSocialAccount;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountAlreadyLinkedException;
use Bambamboole\LaravelOidc\Server\Brokering\SocialAccountManager;
use Bambamboole\LaravelOidc\Server\Shared\Brokering\SocialUser;
use Illuminate\Auth\Access\AuthorizationException;
use Workbench\App\Models\User;

function linkActionUser(string $email): User
{
    return User::create(['name' => 'U', 'email' => $email, 'password' => 'x']);
}

function linkActionSocialUser(string $id = 'g-1'): SocialUser
{
    return new SocialUser($id, 'm@example.com', true, 'M', null, null);
}

it('links an upstream identity to the user', function () {
    $user = linkActionUser('m@example.com');

    app(LinkSocialAccount::class)($user, 'google', linkActionSocialUser());

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-1')?->authenticatable->is($user))->toBeTrue();
});

it('refuses an identity that is already linked to another user', function () {
    $owner = linkActionUser('owner@example.com');
    $other = linkActionUser('other@example.com');
    app(LinkSocialAccount::class)($owner, 'google', linkActionSocialUser());

    expect(fn () => app(LinkSocialAccount::class)($other, 'google', linkActionSocialUser()))
        ->toThrow(SocialAccountAlreadyLinkedException::class);
});

it('unlinks only the owner\'s account', function () {
    $owner = linkActionUser('owner@example.com');
    $other = linkActionUser('other@example.com');
    app(LinkSocialAccount::class)($owner, 'google', linkActionSocialUser());
    $account = app(SocialAccountManager::class)->findAccount('google', 'g-1');

    expect(fn () => app(UnlinkSocialAccount::class)($other, $account))->toThrow(AuthorizationException::class);

    app(UnlinkSocialAccount::class)($owner, $account);

    expect(app(SocialAccountManager::class)->findAccount('google', 'g-1'))->toBeNull();
});
