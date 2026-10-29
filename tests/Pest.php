<?php

declare(strict_types=1);

use Olgun\TrustedDevices\Tests\Support\BootKnobsOffCase;
use Olgun\TrustedDevices\Tests\Support\CustomisedCase;
use Olgun\TrustedDevices\Tests\TestCase;

pest()->extend(TestCase::class)->in('Feature');

// The knobs read at boot, in their other positions: each folder its own app.
pest()->extend(BootKnobsOffCase::class)->in('BootKnobsOff');
pest()->extend(CustomisedCase::class)->in('Customised');
