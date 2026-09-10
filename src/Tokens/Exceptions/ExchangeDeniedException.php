<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exceptions;

use RuntimeException;

/**
 * A token exchange the policy or the exchanger refused. `$error` is the
 * RFC 6749 / RFC 8693 error code the token endpoint answers with.
 */
final class ExchangeDeniedException extends RuntimeException
{
    public function __construct(public readonly string $error, string $description)
    {
        parent::__construct($description);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description);
    }

    public static function accessDenied(string $description): self
    {
        return new self('access_denied', $description);
    }

    public static function invalidTarget(string $description): self
    {
        return new self('invalid_target', $description);
    }

    /**
     * @param  list<string>  $scopes  the scopes that widen the subject token
     */
    public static function invalidScope(array $scopes): self
    {
        return new self('invalid_scope', implode(' ', $scopes));
    }
}
