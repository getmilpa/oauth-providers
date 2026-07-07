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

use Milpa\OAuth\DTO\TwitchUserInfo;
use Milpa\OAuth\Contracts\TwitchOAuthServiceInterface;

/**
 * Twitch OAuth 2.0 protocol implementation.
 *
 * Uses the Twitch Helix API for user info retrieval.
 * Note: Twitch requires the Client-Id header alongside the Bearer token
 * when calling the Helix API.
 */
class TwitchOAuthService implements TwitchOAuthServiceInterface
{
    private const AUTH_ENDPOINT = 'https://id.twitch.tv/oauth2/authorize';
    private const TOKEN_ENDPOINT = 'https://id.twitch.tv/oauth2/token';
    private const USERINFO_ENDPOINT = 'https://api.twitch.tv/helix/users';

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret
    ) {
    }

    /**
     * Build the Twitch authorization URL requesting the user:read:email scope.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => 'user:read:email',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::AUTH_ENDPOINT . '?' . http_build_query($params);
    }

    /**
     * Exchange the authorization code for an access token, then fetch the
     * profile from the Twitch Helix API.
     */
    public function exchangeCode(string $code, string $redirectUri): TwitchUserInfo
    {
        $this->assertConfigured();

        $tokenData = $this->fetchToken($code, $redirectUri);
        return $this->fetchUserInfo($tokenData['access_token']);
    }

    private function assertConfigured(): void
    {
        if (empty($this->clientId) || empty($this->clientSecret)) {
            throw new \RuntimeException('Twitch OAuth not configured: TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET are required');
        }
    }

    /**
     * @return array{access_token: string}
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
            throw new \RuntimeException('Twitch token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string, message?: string}|null $data */
        $data = json_decode($response, true);

        if (isset($data['message'])) {
            throw new \RuntimeException('Twitch token error: ' . $data['message']);
        }

        if (!isset($data['access_token'])) {
            throw new \RuntimeException('access_token missing in Twitch response');
        }

        return $data;
    }

    private function fetchUserInfo(string $accessToken): TwitchUserInfo
    {
        $ch = curl_init(self::USERINFO_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
                'Client-Id: ' . $this->clientId,
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Failed to fetch Twitch user info');
        }

        /** @var array{data?: array<int, array{id?: string, login?: string, display_name?: string, email?: string, profile_image_url?: string}>}|null $result */
        $result = json_decode($response, true);
        $data = $result['data'][0] ?? null;

        if (!$data || !isset($data['id'], $data['login'])) {
            throw new \RuntimeException('Incomplete user data from Twitch');
        }

        return new TwitchUserInfo(
            id: $data['id'],
            login: $data['login'],
            displayName: $data['display_name'] ?? $data['login'],
            email: $data['email'] ?? null,
            profileImageUrl: $data['profile_image_url'] ?? null
        );
    }
}
