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

use Milpa\OAuth\DTO\GitHubUserInfo;
use Milpa\OAuth\Contracts\GitHubOAuthServiceInterface;

/**
 * GitHub OAuth 2.0 protocol implementation.
 *
 * Handles the authorization code flow: build auth URL, exchange code for token,
 * and fetch user info from the GitHub API.
 */
class GitHubOAuthService implements GitHubOAuthServiceInterface
{
    private const AUTH_ENDPOINT = 'https://github.com/login/oauth/authorize';
    private const TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token';
    private const USERINFO_ENDPOINT = 'https://api.github.com/user';

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret
    ) {
    }

    /**
     * Build the GitHub authorization URL requesting the read:user and user:email scopes.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => 'read:user user:email',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::AUTH_ENDPOINT . '?' . http_build_query($params);
    }

    /**
     * Exchange the authorization code for an access token, then fetch the
     * profile from the GitHub REST API.
     */
    public function exchangeCode(string $code, string $redirectUri): GitHubUserInfo
    {
        $this->assertConfigured();

        $tokenData = $this->fetchToken($code, $redirectUri);
        return $this->fetchUserInfo($tokenData['access_token']);
    }

    private function assertConfigured(): void
    {
        if (empty($this->clientId) || empty($this->clientSecret)) {
            throw new \RuntimeException('GitHub OAuth not configured: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required');
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
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
            ],
            CURLOPT_POSTFIELDS => http_build_query([
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $redirectUri,
            ]),
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('GitHub token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string, error?: string}|null $data */
        $data = json_decode($response, true);

        if (isset($data['error'])) {
            throw new \RuntimeException('GitHub token error: ' . $data['error']);
        }

        if (!isset($data['access_token'])) {
            throw new \RuntimeException('access_token missing in GitHub response');
        }

        return $data;
    }

    private function fetchUserInfo(string $accessToken): GitHubUserInfo
    {
        $ch = curl_init(self::USERINFO_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $accessToken,
                'Accept: application/vnd.github+json',
                'User-Agent: Milpa-OAuthPlugin',
            ],
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Failed to fetch GitHub user info');
        }

        /** @var array{id?: int, login?: string, name?: string, email?: string, avatar_url?: string}|null $data */
        $data = json_decode($response, true);

        if (!isset($data['id'], $data['login'])) {
            throw new \RuntimeException('Incomplete user data from GitHub');
        }

        return new GitHubUserInfo(
            id: (string) $data['id'],
            login: $data['login'],
            name: $data['name'] ?? $data['login'],
            email: $data['email'] ?? null,
            avatarUrl: $data['avatar_url'] ?? null
        );
    }
}
