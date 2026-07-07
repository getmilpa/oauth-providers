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

use Milpa\OAuth\Providers\GoogleOAuthService;
use PHPUnit\Framework\TestCase;

class GoogleOAuthServiceTest extends TestCase
{
    public function testGetAuthUrlShape(): void
    {
        $service = new GoogleOAuthService('client-id', 'client-secret');

        $url = $service->getAuthUrl('https://app.example.com/callback/google');

        $this->assertStringStartsWith('https://accounts.google.com/o/oauth2/v2/auth?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'client-id',
            'redirect_uri' => 'https://app.example.com/callback/google',
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'access_type' => 'offline',
            'prompt' => 'consent',
        ], $params);

        // `state` is opt-in: omitted entirely when the caller doesn't pass one,
        // rather than sent empty. CSRF-state generation/storage/verification
        // remains the caller's responsibility (see your login controller);
        // this provider only transports the value.
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new GoogleOAuthService('client-id', 'client-secret');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/google', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new GoogleOAuthService('', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Google OAuth not configured');

        $service->getAuthUrl('https://app.example.com/callback/google');
    }
}
