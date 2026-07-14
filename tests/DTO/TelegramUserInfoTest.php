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

use Milpa\OAuth\DTO\TelegramUserInfo;
use PHPUnit\Framework\TestCase;

class TelegramUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like the Telegram Login Widget's callback payload.
        $payload = [
            'id' => '123456789',
            'first_name' => 'Ada',
            'last_name' => 'Lovelace',
            'username' => 'ada_l',
            'photo_url' => 'https://t.me/i/userpic/320/ada.jpg',
        ];

        $info = new TelegramUserInfo(
            id: (string) $payload['id'],
            firstName: $payload['first_name'] ?? 'User',
            lastName: $payload['last_name'] ?? null,
            username: $payload['username'] ?? null,
            photoUrl: $payload['photo_url'] ?? null
        );

        $this->assertSame([
            'id' => '123456789',
            'first_name' => 'Ada',
            'last_name' => 'Lovelace',
            'username' => 'ada_l',
            'photo_url' => 'https://t.me/i/userpic/320/ada.jpg',
        ], $info->toArray());
    }

    public function testGetFullNameJoinsFirstAndLastName(): void
    {
        $info = new TelegramUserInfo(id: '1', firstName: 'Ada', lastName: 'Lovelace');

        $this->assertSame('Ada Lovelace', $info->getFullName());
    }

    public function testGetFullNameTrimsWhenLastNameIsMissing(): void
    {
        $info = new TelegramUserInfo(id: '1', firstName: 'Ada');

        $this->assertSame('Ada', $info->getFullName());
    }
}
