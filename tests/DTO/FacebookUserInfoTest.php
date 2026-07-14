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

use Milpa\OAuth\DTO\FacebookUserInfo;
use PHPUnit\Framework\TestCase;

class FacebookUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like Facebook's Graph API /me response.
        $payload = [
            'id' => '10159...',
            'name' => 'Grace Hopper',
            'email' => 'grace@example.com',
            'picture' => ['data' => ['url' => 'https://platform-lookaside.example/pic.jpg']],
        ];

        $info = new FacebookUserInfo(
            id: $payload['id'],
            name: $payload['name'],
            email: $payload['email'] ?? null,
            picture: $payload['picture']['data']['url'] ?? null
        );

        $this->assertSame([
            'id' => '10159...',
            'name' => 'Grace Hopper',
            'email' => 'grace@example.com',
            'picture' => 'https://platform-lookaside.example/pic.jpg',
        ], $info->toArray());
    }

    public function testEmailAndPictureAreOptional(): void
    {
        $info = new FacebookUserInfo(id: '10159...', name: 'Grace Hopper');

        $this->assertNull($info->email);
        $this->assertNull($info->picture);
    }
}
