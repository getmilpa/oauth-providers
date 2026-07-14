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

use Milpa\OAuth\DTO\GitLabUserInfo;
use PHPUnit\Framework\TestCase;

class GitLabUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like GitLab's GET /api/v4/user response.
        $payload = [
            'id' => 1,
            'username' => 'raymond_smith',
            'name' => 'Raymond Smith',
            'email' => 'raymond@example.com',
            'avatar_url' => 'https://gitlab.example.com/uploads/-/system/user/avatar/1/avatar.png',
        ];

        $info = new GitLabUserInfo(
            id: (string) $payload['id'],
            username: $payload['username'],
            name: $payload['name'] ?? $payload['username'],
            email: $payload['email'] ?? null,
            avatarUrl: $payload['avatar_url'] ?? null
        );

        $this->assertSame([
            'id' => '1',
            'username' => 'raymond_smith',
            'name' => 'Raymond Smith',
            'email' => 'raymond@example.com',
            'avatar_url' => 'https://gitlab.example.com/uploads/-/system/user/avatar/1/avatar.png',
        ], $info->toArray());
    }

    public function testNameFallsBackToUsernameWhenPayloadOmitsIt(): void
    {
        $info = new GitLabUserInfo(id: '2', username: 'octocat', name: 'octocat');

        $this->assertSame('octocat', $info->name);
        $this->assertNull($info->email);
        $this->assertNull($info->avatarUrl);
    }
}
