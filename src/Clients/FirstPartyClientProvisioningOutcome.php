<?php

declare(strict_types=1);

namespace Bambamboole\LaravelOidc\Clients;

enum FirstPartyClientProvisioningOutcome: string
{
    case Created = 'created';
    case Reconciled = 'reconciled';
    case Rotated = 'rotated';
}
