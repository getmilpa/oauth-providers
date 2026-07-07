<?php

/**
 * This file is part of Milpa OAuth Providers — the OAuth 2.0 / social-login
 * provider protocol layer of the Milpa PHP framework.
 *
 * (c) TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/oauth-providers
 */

declare(strict_types=1);

namespace Milpa\OAuth\Tests\DTO;

use Milpa\OAuth\DTO\GoogleUserInfo;
use PHPUnit\Framework\TestCase;

class GoogleUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like Google's oauth2/v2/userinfo response.
        $payload = [
            'id' => '110169484474386276334',
            'email' => 'ada@example.com',
            'name' => 'Ada Lovelace',
            'picture' => 'https://lh3.googleusercontent.com/a/ada.jpg',
        ];

        $info = new GoogleUserInfo(
            id: $payload['id'],
            email: $payload['email'],
            name: $payload['name'],
            picture: $payload['picture'] ?? null
        );

        $this->assertSame([
            'id' => '110169484474386276334',
            'email' => 'ada@example.com',
            'name' => 'Ada Lovelace',
            'picture' => 'https://lh3.googleusercontent.com/a/ada.jpg',
        ], $info->toArray());
    }

    public function testPictureIsOptional(): void
    {
        $info = new GoogleUserInfo(id: '1', email: 'a@b.com', name: 'A B');

        $this->assertNull($info->picture);
    }
}
