<?php

declare(strict_types=1);

namespace Workbench\App\Enums;

/** A column cast to an enum, for the fingerprint's tests. */
enum Level: string
{
    case Admin = 'admin';
    case Member = 'member';
}
