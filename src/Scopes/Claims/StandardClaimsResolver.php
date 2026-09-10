<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes\Claims;

use Bambamboole\LaravelOidc\Server\Scopes\Contracts\ClaimsResolver;
use Illuminate\Database\Eloquent\Model;

/**
 * Maps the OIDC Core §5.4 standard scopes onto same-named user attributes:
 * `profile` (name, locale from `locale`, zoneinfo from `timezone`,
 * updated_at), `email` (email, email_verified from `email_verified_at`),
 * `phone` (phone_number, phone_number_verified) and `address` (the §5.1.1
 * structured claim from an `address` attribute). An attribute the user
 * lacks omits its claim.
 */
class StandardClaimsResolver implements ClaimsResolver
{
    private const array ADDRESS_MEMBERS = ['formatted', 'street_address', 'locality', 'region', 'postal_code', 'country'];

    /** @return array<string, mixed> */
    public function resolve(ClaimsRequest $request): array
    {
        return $this->claimSet($request)->forScopes($request->scopes);
    }

    protected function claimSet(ClaimsRequest $request): ClaimSet
    {
        $user = $request->user;

        if (! $user instanceof Model) {
            return new ClaimSet;
        }

        $phoneNumber = $user->getAttribute('phone_number');
        $phoneVerified = $user->getAttribute('phone_number_verified');

        return new ClaimSet([
            'profile' => [
                'name' => $user->getAttribute('name'),
                'locale' => $user->getAttribute('locale'),
                'zoneinfo' => $user->getAttribute('timezone'),
                'updated_at' => $user->getAttribute('updated_at')?->getTimestamp(),
            ],
            'email' => [
                'email' => $user->getAttribute('email'),
                'email_verified' => $user->getAttribute('email') !== null
                    ? $user->getAttribute('email_verified_at') !== null
                    : null,
            ],
            'phone' => [
                'phone_number' => is_string($phoneNumber) && $phoneNumber !== '' ? $phoneNumber : null,
                'phone_number_verified' => $phoneNumber !== null && $phoneVerified !== null ? (bool) $phoneVerified : null,
            ],
            'address' => [
                'address' => $this->address($user->getAttribute('address')),
            ],
        ]);
    }

    /**
     * OIDC Core §5.1.1: a string is the `formatted` member; an array keeps
     * the standard members it carries.
     *
     * @return array<string, string>|null
     */
    private function address(mixed $address): ?array
    {
        if (is_string($address)) {
            return trim($address) !== '' ? ['formatted' => $address] : null;
        }

        if (! is_array($address)) {
            return null;
        }

        $members = [];

        foreach (self::ADDRESS_MEMBERS as $member) {
            $value = $address[$member] ?? null;

            if (is_string($value) && $value !== '') {
                $members[$member] = $value;
            }
        }

        return $members !== [] ? $members : null;
    }
}
