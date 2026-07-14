<?php

/**
 * This file is part of Milpa OAuth Providers — the OAuth 2.0 / social-login
 * provider protocol layer of the Milpa PHP framework.
 *
 * (c) Rodrigo Vicente - TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/oauth-providers
 */

declare(strict_types=1);

namespace Milpa\OAuth\Tests\DTO;

use Milpa\OAuth\DTO\AppleUserInfo;
use PHPUnit\Framework\TestCase;

class AppleUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFields(): void
    {
        $info = new AppleUserInfo(id: '001234.abcd', email: 'user@privaterelay.appleid.com', name: 'Ada Lovelace');

        $this->assertSame([
            'id' => '001234.abcd',
            'email' => 'user@privaterelay.appleid.com',
            'name' => 'Ada Lovelace',
        ], $info->toArray());
    }

    public function testEmailAndNameAreOptional(): void
    {
        // Apple only sends the name on the FIRST authorization; subsequent
        // logins only carry `sub` (id) and optionally the email.
        $info = new AppleUserInfo(id: '001234.abcd');

        $this->assertNull($info->email);
        $this->assertNull($info->name);
        $this->assertSame(['id' => '001234.abcd', 'email' => null, 'name' => null], $info->toArray());
    }
}
