<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Scopes\Claims;

/**
 * Which surface the claims are being resolved for. A resolver may emit a claim
 * into the id_token but not userinfo, or the other way round.
 */
enum ClaimsAudience: string
{
    case IdToken = 'id_token';
    case Userinfo = 'userinfo';
}
