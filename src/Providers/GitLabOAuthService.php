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

use Milpa\OAuth\DTO\GitLabUserInfo;
use Milpa\OAuth\Contracts\GitLabOAuthServiceInterface;

/**
 * GitLab OAuth 2.0 protocol implementation.
 *
 * Supports both gitlab.com and self-hosted instances via configurable instanceUrl.
 * Set GITLAB_INSTANCE_URL to your private GitLab base URL (e.g. https://git.mycompany.com).
 * Defaults to https://gitlab.com when not set.
 */
class GitLabOAuthService implements GitLabOAuthServiceInterface
{
    private const DEFAULT_INSTANCE = 'https://gitlab.com';

    private readonly string $instanceUrl;

    public function __construct(
        private readonly string $clientId,
        private readonly string $clientSecret,
        string $instanceUrl = ''
    ) {
        $url = !empty($instanceUrl) ? $instanceUrl : self::DEFAULT_INSTANCE;
        $this->instanceUrl = rtrim($url, '/');
    }

    /**
     * Build the authorization URL against the configured GitLab instance
     * (gitlab.com by default, or the self-hosted instanceUrl given at construction).
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => 'read_user',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return $this->instanceUrl . '/oauth/authorize?' . http_build_query($params);
    }

    /**
     * Exchange the authorization code for an access token, then fetch the
     * profile from the configured instance's API.
     */
    public function exchangeCode(string $code, string $redirectUri): GitLabUserInfo
    {
        $this->assertConfigured();

        $tokenData = $this->fetchToken($code, $redirectUri);
        return $this->fetchUserInfo($tokenData['access_token']);
    }

    public function getInstanceUrl(): string
    {
        return $this->instanceUrl;
    }

    private function assertConfigured(): void
    {
        if (empty($this->clientId) || empty($this->clientSecret)) {
            throw new \RuntimeException('GitLab OAuth not configured: GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET are required');
        }
    }

    /**
     * @return array{access_token: string}
     */
    private function fetchToken(string $code, string $redirectUri): array
    {
        $tokenEndpoint = $this->instanceUrl . '/oauth/token';

        $ch = curl_init($tokenEndpoint);
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
            throw new \RuntimeException('GitLab token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string, error?: string, error_description?: string}|null $data */
        $data = json_decode($response, true);

        if (isset($data['error'])) {
            throw new \RuntimeException('GitLab token error: ' . ($data['error_description'] ?? $data['error']));
        }

        if (!isset($data['access_token'])) {
            throw new \RuntimeException('access_token missing in GitLab response');
        }

        return $data;
    }

    private function fetchUserInfo(string $accessToken): GitLabUserInfo
    {
        $userEndpoint = $this->instanceUrl . '/api/v4/user';

        $ch = curl_init($userEndpoint);
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
            throw new \RuntimeException('Failed to fetch GitLab user info');
        }

        /** @var array{id?: int, username?: string, name?: string, email?: string, avatar_url?: string}|null $data */
        $data = json_decode($response, true);

        if (!isset($data['id'], $data['username'])) {
            throw new \RuntimeException('Incomplete user data from GitLab');
        }

        return new GitLabUserInfo(
            id: (string) $data['id'],
            username: $data['username'],
            name: $data['name'] ?? $data['username'],
            email: $data['email'] ?? null,
            avatarUrl: $data['avatar_url'] ?? null
        );
    }
}
