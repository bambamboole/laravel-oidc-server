<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Shared\Realms;

use Illuminate\Database\Eloquent\Builder;

/**
 * Scoping is explicit rather than a global scope: administration reads across
 * realms on purpose, and a global scope that half the callers have to disable
 * hides the very isolation it is supposed to guarantee.
 */
trait BelongsToRealm
{
    /**
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeInRealm(Builder $query, ?string $realm = null): Builder
    {
        return $query->where($this->getTable().'.realm_id', $realm ?? self::currentRealm());
    }

    public static function currentRealm(): string
    {
        return app(RealmResolver::class)->current()->identifier();
    }
}
