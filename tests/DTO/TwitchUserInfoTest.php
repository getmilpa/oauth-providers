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

use Milpa\OAuth\DTO\TwitchUserInfo;
use PHPUnit\Framework\TestCase;

class TwitchUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like a single entry of Twitch Helix's GET /users `data` array.
        $payload = [
            'id' => '141981764',
            'login' => 'twitchdev',
            'display_name' => 'TwitchDev',
            'email' => 'dev@twitch.tv',
            'profile_image_url' => 'https://static-cdn.jtvnw.net/jtv_user_pictures/twitchdev.png',
        ];

        $info = new TwitchUserInfo(
            id: $payload['id'],
            login: $payload['login'],
            displayName: $payload['display_name'] ?? $payload['login'],
            email: $payload['email'] ?? null,
            profileImageUrl: $payload['profile_image_url'] ?? null
        );

        $this->assertSame([
            'id' => '141981764',
            'login' => 'twitchdev',
            'display_name' => 'TwitchDev',
            'email' => 'dev@twitch.tv',
            'profile_image_url' => 'https://static-cdn.jtvnw.net/jtv_user_pictures/twitchdev.png',
        ], $info->toArray());
    }

    public function testDisplayNameFallsBackToLoginWhenPayloadOmitsIt(): void
    {
        $info = new TwitchUserInfo(id: '1', login: 'octocat', displayName: 'octocat');

        $this->assertSame('octocat', $info->displayName);
        $this->assertNull($info->email);
        $this->assertNull($info->profileImageUrl);
    }
}
