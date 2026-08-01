<?php

declare(strict_types=1);

use Bambamboole\LaravelOidc\Server\Support\EnvironmentFile;
use Bambamboole\LaravelOidc\Server\Support\EnvironmentWriteException;

function environmentFileFixture(string $contents): string
{
    $path = temporaryTestDirectory('envfile').'/.env';
    file_put_contents($path, $contents);

    return $path;
}

it('upserts an existing key and appends a new one in a single write', function () {
    $path = environmentFileFixture("APP_NAME=Testing\nOIDC_FIRST_PARTY_CLIENT=stale\n");

    (new EnvironmentFile($path))->write([
        'OIDC_FIRST_PARTY_CLIENT' => 'abc-123',
        'OIDC_FIRST_PARTY_TRUSTED' => 'true',
    ]);

    $contents = (string) file_get_contents($path);

    expect(substr_count($contents, 'OIDC_FIRST_PARTY_CLIENT='))->toBe(1)
        ->and($contents)->toContain('OIDC_FIRST_PARTY_CLIENT=abc-123')
        ->and($contents)->toContain('OIDC_FIRST_PARTY_TRUSTED=true')
        ->and($contents)->toContain('APP_NAME=Testing');
});

it('applies the encoder to every written value', function () {
    $path = environmentFileFixture("APP_NAME=Testing\n");

    (new EnvironmentFile($path))->write(
        ['OIDC_PRIVATE_KEY' => "line1\nline2"],
        fn (string $value): string => '"'.str_replace("\n", '\n', $value).'"',
    );

    expect((string) file_get_contents($path))->toContain('OIDC_PRIVATE_KEY="line1\nline2"');
});

it('replaces the target atomically without leaving a temp file behind', function () {
    $path = environmentFileFixture("APP_NAME=Testing\n");

    (new EnvironmentFile($path))->write(['OIDC_FIRST_PARTY_CLIENT' => 'abc-123']);

    $siblings = glob(dirname($path).'/*.tmp') ?: [];

    expect($siblings)->toBe([])
        ->and((string) file_get_contents($path))->toContain('OIDC_FIRST_PARTY_CLIENT=abc-123');
});

it('preserves the target file permissions across the atomic write', function () {
    $path = environmentFileFixture("APP_NAME=Testing\n");
    chmod($path, 0600);

    (new EnvironmentFile($path))->write(['OIDC_PRIVATE_KEY' => 'secret']);

    expect(fileperms($path) & 0777)->toBe(0600);
});

it('throws when the environment file cannot be read', function () {
    (new EnvironmentFile('/nonexistent/dir/.env'))->write(['A' => 'b']);
})->throws(EnvironmentWriteException::class);

it('reads a plain value back and returns null for absent keys', function () {
    $path = environmentFileFixture("APP_NAME=Testing\nOIDC_FIRST_PARTY_CLIENT=abc-123\nEMPTY=\n");
    $store = new EnvironmentFile($path);

    expect($store->value('OIDC_FIRST_PARTY_CLIENT'))->toBe('abc-123')
        ->and($store->value('APP_NAME'))->toBe('Testing')
        ->and($store->value('EMPTY'))->toBeNull()
        ->and($store->value('MISSING'))->toBeNull();
});

it('reads quoted values without their quotes', function () {
    $path = environmentFileFixture("SINGLE='with spaces'\nDOUBLE=\"quo # ted\"\n");
    $store = new EnvironmentFile($path);

    expect($store->value('SINGLE'))->toBe('with spaces')
        ->and($store->value('DOUBLE'))->toBe('quo # ted');
});

it('ignores comment lines and strips inline comments from unquoted values', function () {
    $path = environmentFileFixture("# OIDC_ISSUER=commented\nOIDC_ISSUER=https://op.test # the provider\n");

    expect((new EnvironmentFile($path))->value('OIDC_ISSUER'))->toBe('https://op.test');
});

it('returns null when the environment file does not exist', function () {
    expect((new EnvironmentFile('/nonexistent/dir/.env'))->value('APP_NAME'))->toBeNull();
});

it('round-trips values written through write()', function () {
    $path = environmentFileFixture("APP_NAME=Testing\n");
    $store = new EnvironmentFile($path);

    $store->write(['OIDC_RP_CLIENT_SECRET' => 'plain-secret']);
    $store->write(
        ['OIDC_PRIVATE_KEY' => "line1\nline2"],
        fn (string $value): string => '"'.str_replace("\n", '\n', $value).'"',
    );

    expect($store->value('OIDC_RP_CLIENT_SECRET'))->toBe('plain-secret')
        ->and($store->value('OIDC_PRIVATE_KEY'))->toBe("line1\nline2");
});

it('encodes values identically for LF, CRLF, and bare-CR line endings', function () {
    $encoded = EnvironmentFile::encode("-----BEGIN X-----\nabc\n-----END X-----\n");

    expect($encoded)->toBe('"-----BEGIN X-----\nabc\n-----END X-----"')
        ->and(EnvironmentFile::encode("-----BEGIN X-----\r\nabc\r\n-----END X-----\r\n"))->toBe($encoded)
        ->and(EnvironmentFile::encode("-----BEGIN X-----\rabc\r-----END X-----\r"))->toBe($encoded)
        ->and($encoded)->not->toContain("\r");
});

it('round-trips a CRLF value through encode() and value()', function () {
    $path = environmentFileFixture("APP_NAME=Testing\n");

    (new EnvironmentFile($path))->write(['OIDC_PRIVATE_KEY' => "line1\r\nline2"], EnvironmentFile::encode(...));

    expect((new EnvironmentFile($path))->value('OIDC_PRIVATE_KEY'))->toBe("line1\nline2");
});
