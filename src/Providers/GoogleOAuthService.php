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

namespace Milpa\OAuth\Providers;

use Milpa\OAuth\DTO\GoogleUserInfo;
use Milpa\OAuth\Contracts\GoogleOAuthServiceInterface;

/**
 * Google OAuth 2.0 protocol implementation.
 *
 * Handles the authorization code flow: build auth URL, exchange code for token,
 * and fetch user info. Each consumer plugin provides its own redirectUri.
 */
class GoogleOAuthService implements GoogleOAuthServiceInterface
{
    private const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
    private const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
    private const USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v2/userinfo';

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret
    ) {
    }

    /**
     * Build the Google consent-screen URL, requesting offline access and forcing
     * the consent prompt so a refresh token is issued on every authorization.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'access_type' => 'offline',
            'prompt' => 'consent',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::AUTH_ENDPOINT . '?' . http_build_query($params);
    }

    /**
     * Exchange the authorization code for an access token, then fetch the
     * profile from Google's userinfo endpoint.
     */
    public function exchangeCode(string $code, string $redirectUri): GoogleUserInfo
    {
        $this->assertConfigured();

        $tokenData = $this->fetchToken($code, $redirectUri);
        return $this->fetchUserInfo($tokenData['access_token']);
    }

    private function assertConfigured(): void
    {
        if (empty($this->clientId) || empty($this->clientSecret)) {
            throw new \RuntimeException('Google OAuth not configured: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required');
        }
    }

    /**
     * @return array{access_token: string, refresh_token?: string}
     */
    private function fetchToken(string $code, string $redirectUri): array
    {
        $ch = curl_init(self::TOKEN_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ]),
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Google token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string}|null $data */
        $data = json_decode($response, true);

        if (!isset($data['access_token'])) {
            throw new \RuntimeException('access_token missing in Google response');
        }

        return $data;
    }

    private function fetchUserInfo(string $accessToken): GoogleUserInfo
    {
        $ch = curl_init(self::USERINFO_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Failed to fetch Google user info');
        }

        /** @var array{id?: string, email?: string, name?: string, picture?: string}|null $data */
        $data = json_decode($response, true);

        if (!isset($data['id'], $data['email'], $data['name'])) {
            throw new \RuntimeException('Incomplete user data from Google');
        }

        return new GoogleUserInfo(
            id: $data['id'],
            email: $data['email'],
            name: $data['name'],
            picture: $data['picture'] ?? null
        );
    }
}
