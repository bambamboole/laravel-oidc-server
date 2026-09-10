<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens\Exceptions;

use RuntimeException;

/**
 * An access-token trigger denied the issuance; the message is the reason
 * the trigger gave.
 */
final class TokenIssuanceDeniedException extends RuntimeException {}
