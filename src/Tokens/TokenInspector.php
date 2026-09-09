<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Tokens;

use Bambamboole\LaravelOidc\Server\Shared\Keys\SigningKeys;
use Bambamboole\LaravelOidc\Server\Tokens\Models\Token;
use Illuminate\Contracts\Encryption\Encrypter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptTrait;
use Throwable;

class TokenInspector
{
    use CryptTrait;

    public function __construct(private readonly SigningKeys $signingKeys) {}

    public function accessToken(string $jwt): ?Token
    {
        $parsed = $this->parse($jwt);

        return $parsed !== null ? $this->tokenForParsed($parsed) : null;
    }

    public function parse(string $jwt): ?Plain
    {
        try {
            $parsed = (new Parser(new JoseEncoder))->parse($jwt);
        } catch (Throwable) {
            return null;
        }

        if (! $parsed instanceof Plain) {
            return null;
        }

        $validator = new Validator;

        foreach ($this->signingKeys->verificationKeys() as $key) {
            if ($validator->validate($parsed, new SignedWith(new Sha256, InMemory::plainText($key->publicKeyPem)))) {
                return $parsed;
            }
        }

        return null;
    }

    public function tokenForParsed(Plain $parsed): ?Token
    {
        $jti = $parsed->claims()->get('jti');

        return is_string($jti) ? Token::query()->inRealm()->find($jti) : null;
    }

    public function refreshTokenPayload(string $encrypted): ?object
    {
        $this->encryptionKey ??= app(Encrypter::class)->getKey();

        try {
            $payload = json_decode($this->decrypt($encrypted));
        } catch (Throwable) {
            return null;
        }

        return is_object($payload) ? $payload : null;
    }
}
