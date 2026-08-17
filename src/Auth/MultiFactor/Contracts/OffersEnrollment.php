<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Contracts;

use Bambamboole\LaravelOidc\Server\Auth\MultiFactor\Data\EnrollmentOption;

/**
 * Declares the ways a provider can be enrolled in, so a setup surface can build
 * its method picker from the registry instead of type-checking concrete
 * providers. Return an empty list to stay out of the picker — that is what a
 * backup provider like recovery codes does, since it is generated rather than
 * chosen.
 */
interface OffersEnrollment
{
    /**
     * @return list<EnrollmentOption>
     */
    public function enrollmentOptions(): array;
}
