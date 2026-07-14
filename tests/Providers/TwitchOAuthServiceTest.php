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

use Milpa\OAuth\Providers\TwitchOAuthService;
use PHPUnit\Framework\TestCase;

class TwitchOAuthServiceTest extends TestCase
{
    public function testGetAuthUrlShape(): void
    {
        $service = new TwitchOAuthService('client-id', 'client-secret');

        $url = $service->getAuthUrl('https://app.example.com/callback/twitch');

        $this->assertStringStartsWith('https://id.twitch.tv/oauth2/authorize?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'client-id',
            'redirect_uri' => 'https://app.example.com/callback/twitch',
            'response_type' => 'code',
            'scope' => 'user:read:email',
        ], $params);
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new TwitchOAuthService('client-id', 'client-secret');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/twitch', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new TwitchOAuthService('', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Twitch OAuth not configured');

        $service->getAuthUrl('https://app.example.com/callback/twitch');
    }
}
