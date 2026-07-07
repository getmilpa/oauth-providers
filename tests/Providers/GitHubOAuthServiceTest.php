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

namespace Milpa\OAuth\Tests\Providers;

use Milpa\OAuth\Providers\GitHubOAuthService;
use PHPUnit\Framework\TestCase;

class GitHubOAuthServiceTest extends TestCase
{
    public function testGetAuthUrlShape(): void
    {
        $service = new GitHubOAuthService('client-id', 'client-secret');

        $url = $service->getAuthUrl('https://app.example.com/callback/github');

        $this->assertStringStartsWith('https://github.com/login/oauth/authorize?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'client-id',
            'redirect_uri' => 'https://app.example.com/callback/github',
            'scope' => 'read:user user:email',
        ], $params);

        // `state` is opt-in — see GoogleOAuthServiceTest for the same coverage.
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new GitHubOAuthService('client-id', 'client-secret');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/github', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new GitHubOAuthService('', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitHub OAuth not configured');

        $service->getAuthUrl('https://app.example.com/callback/github');
    }
}
