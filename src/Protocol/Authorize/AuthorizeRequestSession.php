<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Protocol\Authorize;

use Bambamboole\LaravelOidc\Server\Protocol\InvalidAuthTokenException;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Holds the authorization request across the consent screen. The auth token
 * handed to the view must come back with the decision, so a forged approve
 * request cannot complete somebody else's pending authorization.
 */
final class AuthorizeRequestSession
{
    private const string TOKEN_KEY = 'authToken';

    private const string REQUEST_KEY = 'authRequest';

    /** @return string the auth token the consent form must echo back */
    public function stash(Request $request, AuthorizeRequest $authorizeRequest): string
    {
        $token = Str::random();

        $request->session()->put(self::TOKEN_KEY, $token);
        $request->session()->put(self::REQUEST_KEY, serialize($authorizeRequest));

        return $token;
    }

    public function pull(Request $request): AuthorizeRequest
    {
        if ($request->isNotFilled('auth_token')
            || $request->session()->pull(self::TOKEN_KEY) !== $request->input('auth_token')) {
            $request->session()->forget([self::TOKEN_KEY, self::REQUEST_KEY]);

            throw InvalidAuthTokenException::different();
        }

        $serialized = $request->session()->pull(self::REQUEST_KEY);

        return $this->restore($serialized)
            ?? throw new RuntimeException('Authorization request was not present in the session.');
    }

    public function peek(Request $request): ?AuthorizeRequest
    {
        return $this->restore($request->session()->get(self::REQUEST_KEY));
    }

    private function restore(mixed $serialized): ?AuthorizeRequest
    {
        if (! is_string($serialized)) {
            return null;
        }

        $authorizeRequest = unserialize($serialized, ['allowed_classes' => [AuthorizeRequest::class]]);

        return $authorizeRequest instanceof AuthorizeRequest ? $authorizeRequest : null;
    }
}
