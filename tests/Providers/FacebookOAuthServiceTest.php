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

use Milpa\OAuth\Providers\FacebookOAuthService;
use PHPUnit\Framework\TestCase;

class FacebookOAuthServiceTest extends TestCase
{
    public function testGetAuthUrlShape(): void
    {
        $service = new FacebookOAuthService('app-id', 'app-secret');

        $url = $service->getAuthUrl('https://app.example.com/callback/facebook');

        $this->assertStringStartsWith('https://www.facebook.com/v21.0/dialog/oauth?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'app-id',
            'redirect_uri' => 'https://app.example.com/callback/facebook',
            'scope' => 'email public_profile',
            'response_type' => 'code',
        ], $params);
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new FacebookOAuthService('app-id', 'app-secret');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/facebook', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new FacebookOAuthService('', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Facebook OAuth not configured');

        $service->getAuthUrl('https://app.example.com/callback/facebook');
    }
}
