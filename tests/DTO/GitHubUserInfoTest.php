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

use Milpa\OAuth\DTO\GitHubUserInfo;
use PHPUnit\Framework\TestCase;

class GitHubUserInfoTest extends TestCase
{
    public function testToArrayMapsAllFieldsFromSamplePayload(): void
    {
        // Shaped like GitHub's GET /user response — id arrives as int, we store it as string.
        $payload = [
            'id' => 583231,
            'login' => 'octocat',
            'name' => 'The Octocat',
            'email' => 'octocat@github.com',
            'avatar_url' => 'https://avatars.githubusercontent.com/u/583231',
        ];

        $info = new GitHubUserInfo(
            id: (string) $payload['id'],
            login: $payload['login'],
            name: $payload['name'] ?? $payload['login'],
            email: $payload['email'] ?? null,
            avatarUrl: $payload['avatar_url'] ?? null
        );

        $this->assertSame([
            'id' => '583231',
            'login' => 'octocat',
            'name' => 'The Octocat',
            'email' => 'octocat@github.com',
            'avatar_url' => 'https://avatars.githubusercontent.com/u/583231',
        ], $info->toArray());
    }

    public function testNameFallsBackToLoginWhenPayloadOmitsIt(): void
    {
        // GitHub's `name` field is nullable when the user hasn't set a display name;
        // the service falls back to `login` before constructing the DTO.
        $payload = ['id' => 1, 'login' => 'mojombo', 'name' => null];

        $info = new GitHubUserInfo(
            id: (string) $payload['id'],
            login: $payload['login'],
            name: $payload['name'] ?? $payload['login']
        );

        $this->assertSame('mojombo', $info->name);
        $this->assertNull($info->email);
        $this->assertNull($info->avatarUrl);
    }
}
