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

        $phoneNumber = $this->attribute($user, 'phone_number');
        $phoneVerified = $this->attribute($user, 'phone_number_verified');

        return new ClaimSet([
            'profile' => [
                'name' => $this->attribute($user, 'name'),
                'locale' => $this->attribute($user, 'locale'),
                'zoneinfo' => $this->attribute($user, 'timezone'),
                'updated_at' => $this->attribute($user, 'updated_at')?->getTimestamp(),
            ],
            'email' => [
                'email' => $this->attribute($user, 'email'),
                'email_verified' => $this->attribute($user, 'email') !== null
                    ? $this->attribute($user, 'email_verified_at') !== null
                    : null,
            ],
            'phone' => [
                'phone_number' => is_string($phoneNumber) && $phoneNumber !== '' ? $phoneNumber : null,
                'phone_number_verified' => $phoneNumber !== null && $phoneVerified !== null ? (bool) $phoneVerified : null,
            ],
            'address' => [
                'address' => $this->address($this->attribute($user, 'address')),
            ],
        ]);
    }

    /**
     * Reads through the model so casts and accessors apply, but never a column
     * the model does not carry: a strict model would throw on the lookup.
     */
    private function attribute(Model $user, string $key): mixed
    {
        return $user->hasAttribute($key) ? $user->getAttribute($key) : null;
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
