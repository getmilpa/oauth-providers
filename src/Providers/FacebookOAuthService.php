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

namespace Milpa\OAuth\Providers;

use Milpa\OAuth\DTO\FacebookUserInfo;
use Milpa\OAuth\Contracts\FacebookOAuthServiceInterface;

/**
 * Facebook OAuth 2.0 protocol implementation.
 *
 * Uses the Facebook Graph API v21.0 for user info retrieval.
 */
class FacebookOAuthService implements FacebookOAuthServiceInterface
{
    private const API_VERSION = 'v21.0';
    private const AUTH_ENDPOINT = 'https://www.facebook.com/' . self::API_VERSION . '/dialog/oauth';
    private const TOKEN_ENDPOINT = 'https://graph.facebook.com/' . self::API_VERSION . '/oauth/access_token';
    private const USERINFO_ENDPOINT = 'https://graph.facebook.com/' . self::API_VERSION . '/me';

    public function __construct(
        private readonly string $appId,
        private readonly string $appSecret
    ) {
    }

    /**
     * Build the Facebook Login dialog URL requesting the email and public_profile scopes.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->appId,
            'redirect_uri' => $redirectUri,
            'scope' => 'email public_profile',
            'response_type' => 'code',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::AUTH_ENDPOINT . '?' . http_build_query($params);
    }

    /**
     * Exchange the authorization code for an access token, then fetch the
     * profile from the Facebook Graph API.
     */
    public function exchangeCode(string $code, string $redirectUri): FacebookUserInfo
    {
        $this->assertConfigured();

        $tokenData = $this->fetchToken($code, $redirectUri);
        return $this->fetchUserInfo($tokenData['access_token']);
    }

    private function assertConfigured(): void
    {
        if (empty($this->appId) || empty($this->appSecret)) {
            throw new \RuntimeException('Facebook OAuth not configured: FACEBOOK_APP_ID and FACEBOOK_APP_SECRET are required');
        }
    }

    /**
     * @return array{access_token: string}
     */
    private function fetchToken(string $code, string $redirectUri): array
    {
        $url = self::TOKEN_ENDPOINT . '?' . http_build_query([
            'code' => $code,
            'client_id' => $this->appId,
            'client_secret' => $this->appSecret,
            'redirect_uri' => $redirectUri,
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Facebook token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string, error?: array{message?: string}}|null $data */
        $data = json_decode($response, true);

        if (isset($data['error'])) {
            throw new \RuntimeException('Facebook token error: ' . ($data['error']['message'] ?? 'unknown'));
        }

        if (!isset($data['access_token'])) {
            throw new \RuntimeException('access_token missing in Facebook response');
        }

        return $data;
    }

    private function fetchUserInfo(string $accessToken): FacebookUserInfo
    {
        $url = self::USERINFO_ENDPOINT . '?' . http_build_query([
            'fields' => 'id,name,email,picture.type(large)',
            'access_token' => $accessToken,
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Failed to fetch Facebook user info');
        }

        /** @var array{id?: string, name?: string, email?: string, picture?: array{data?: array{url?: string}}}|null $data */
        $data = json_decode($response, true);

        if (!isset($data['id'], $data['name'])) {
            throw new \RuntimeException('Incomplete user data from Facebook');
        }

        return new FacebookUserInfo(
            id: $data['id'],
            name: $data['name'],
            email: $data['email'] ?? null,
            picture: $data['picture']['data']['url'] ?? null
        );
    }
}
