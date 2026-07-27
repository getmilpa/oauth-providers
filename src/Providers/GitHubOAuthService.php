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

use Milpa\OAuth\Contracts\GitHubOAuthServiceInterface;
use Milpa\OAuth\DTO\GitHubUserInfo;
use Milpa\OAuth\Http\CurlTransport;
use Milpa\OAuth\Http\HttpTransportInterface;

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

    private readonly HttpTransportInterface $http;

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret,
        ?HttpTransportInterface $transport = null,
    ) {
        $this->http = $transport ?? new CurlTransport();
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
        ['status' => $httpCode, 'body' => $response] = $this->http->post(
            self::TOKEN_ENDPOINT,
            [
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'redirect_uri' => $redirectUri,
            ],
            ['Accept: application/json'],
        );

        if ($httpCode !== 200) {
            throw new \RuntimeException('GitHub token exchange failed: ' . ($response !== '' ? $response : 'no response'));
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
        ['status' => $httpCode, 'body' => $response] = $this->http->get(self::USERINFO_ENDPOINT, [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/vnd.github+json',
            'User-Agent: Milpa-OAuthPlugin',
        ]);

        if ($httpCode !== 200) {
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
