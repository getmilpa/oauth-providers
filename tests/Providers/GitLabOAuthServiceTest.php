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

namespace Milpa\OAuth\Tests\Providers;

use Milpa\OAuth\Providers\GitLabOAuthService;
use PHPUnit\Framework\TestCase;

class GitLabOAuthServiceTest extends TestCase
{
    public function testGetAuthUrlDefaultsToGitlabDotCom(): void
    {
        $service = new GitLabOAuthService('client-id', 'client-secret');

        $this->assertSame('https://gitlab.com', $service->getInstanceUrl());

        $url = $service->getAuthUrl('https://app.example.com/callback/gitlab');

        $this->assertStringStartsWith('https://gitlab.com/oauth/authorize?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'client-id',
            'redirect_uri' => 'https://app.example.com/callback/gitlab',
            'response_type' => 'code',
            'scope' => 'read_user',
        ], $params);
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new GitLabOAuthService('client-id', 'client-secret');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/gitlab', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlHonoursSelfHostedInstanceUrl(): void
    {
        $service = new GitLabOAuthService('client-id', 'client-secret', 'https://git.mycompany.com/');

        // Trailing slash is trimmed.
        $this->assertSame('https://git.mycompany.com', $service->getInstanceUrl());

        $url = $service->getAuthUrl('https://app.example.com/callback/gitlab');

        $this->assertStringStartsWith('https://git.mycompany.com/oauth/authorize?', $url);
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new GitLabOAuthService('', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitLab OAuth not configured');

        $service->getAuthUrl('https://app.example.com/callback/gitlab');
    }
}
