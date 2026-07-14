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

use Milpa\OAuth\DTO\AppleUserInfo;
use Milpa\OAuth\Contracts\AppleOAuthServiceInterface;

/**
 * Apple Sign In OAuth 2.0 protocol implementation.
 *
 * Apple uses a JWT-based client secret generated from a private key,
 * and returns user info inside an id_token (JWT) rather than a userinfo endpoint.
 *
 * IMPORTANT: Apple only sends the user's name on the FIRST authorization.
 * The callback uses response_mode=form_post, so the code arrives via POST body.
 *
 * Required credentials:
 * - APPLE_CLIENT_ID    (Services ID, e.g. com.myapp.auth)
 * - APPLE_TEAM_ID      (10-char Apple Developer Team ID)
 * - APPLE_KEY_ID       (Key ID from Apple Developer Console)
 * - APPLE_PRIVATE_KEY  (Contents of the .p8 file)
 */
class AppleOAuthService implements AppleOAuthServiceInterface
{
    private const AUTH_ENDPOINT = 'https://appleid.apple.com/auth/authorize';
    private const TOKEN_ENDPOINT = 'https://appleid.apple.com/auth/token';

    public function __construct(
        private readonly string $clientId,
        private readonly string $teamId,
        private readonly string $keyId,
        private readonly string $privateKey
    ) {
    }

    /**
     * Build the Apple Sign In authorization URL with response_mode=form_post,
     * requesting the name and email scopes.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string
    {
        $this->assertConfigured();

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
            'scope' => 'name email',
            'response_mode' => 'form_post',
        ];

        if ($state !== null) {
            $params['state'] = $state;
        }

        return self::AUTH_ENDPOINT . '?' . http_build_query($params);
    }

    /**
     * Generate a JWT client secret, exchange the code for an id_token, and decode
     * the user info it carries — Apple has no separate userinfo endpoint.
     */
    public function exchangeCode(string $code, string $redirectUri, ?string $userName = null): AppleUserInfo
    {
        $this->assertConfigured();

        $clientSecret = $this->generateClientSecret();
        $tokenData = $this->fetchToken($code, $redirectUri, $clientSecret);

        return $this->parseIdToken($tokenData['id_token'], $userName);
    }

    private function assertConfigured(): void
    {
        if (empty($this->clientId) || empty($this->teamId) || empty($this->keyId) || empty($this->privateKey)) {
            throw new \RuntimeException(
                'Apple Sign In not configured: APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY are required'
            );
        }
    }

    /**
     * Generate a JWT client secret signed with the Apple private key.
     *
     * Apple requires a short-lived JWT (max 6 months) as the client_secret.
     */
    private function generateClientSecret(): string
    {
        $header = [
            'alg' => 'ES256',
            'kid' => $this->keyId,
        ];

        $now = time();
        $claims = [
            'iss' => $this->teamId,
            'iat' => $now,
            'exp' => $now + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $this->clientId,
        ];

        $headerEncoded = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $claimsEncoded = $this->base64UrlEncode(json_encode($claims, JSON_THROW_ON_ERROR));

        $signingInput = $headerEncoded . '.' . $claimsEncoded;

        $privateKeyResource = openssl_pkey_get_private($this->privateKey);
        if ($privateKeyResource === false) {
            throw new \RuntimeException('Invalid Apple private key');
        }

        $signature = '';
        $success = openssl_sign($signingInput, $signature, $privateKeyResource, OPENSSL_ALGO_SHA256);

        if (!$success) {
            throw new \RuntimeException('Failed to sign Apple client secret');
        }

        // Convert DER signature to raw R+S format for ES256
        $signature = $this->derToRaw($signature);

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }

    /**
     * @return array{access_token: string, id_token: string}
     */
    private function fetchToken(string $code, string $redirectUri, string $clientSecret): array
    {
        $ch = curl_init(self::TOKEN_ENDPOINT);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'code' => $code,
                'client_id' => $this->clientId,
                'client_secret' => $clientSecret,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ]),
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new \RuntimeException('Apple token exchange failed: ' . ($response ?: 'no response'));
        }

        /** @var array{access_token?: string, id_token?: string, error?: string}|null $data */
        $data = json_decode($response, true);

        if (isset($data['error'])) {
            throw new \RuntimeException('Apple token error: ' . $data['error']);
        }

        if (!isset($data['id_token'])) {
            throw new \RuntimeException('id_token missing in Apple response');
        }

        return $data;
    }

    /**
     * Parse the id_token JWT to extract user info.
     *
     * Note: In production, you should verify the JWT signature against Apple's public keys.
     * For simplicity, we decode the payload without verification since the token comes
     * directly from Apple's token endpoint over HTTPS.
     */
    private function parseIdToken(string $idToken, ?string $userName): AppleUserInfo
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid Apple id_token format');
        }

        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);

        if (!isset($payload['sub'])) {
            throw new \RuntimeException('sub claim missing in Apple id_token');
        }

        return new AppleUserInfo(
            id: $payload['sub'],
            email: $payload['email'] ?? null,
            name: $userName
        );
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Convert a DER-encoded ECDSA signature to the raw R+S format required by JWT.
     */
    private function derToRaw(string $der): string
    {
        $offset = 2;
        $rLength = ord($der[$offset + 1]);
        $r = substr($der, $offset + 2, $rLength);
        $offset += 2 + $rLength;
        $sLength = ord($der[$offset + 1]);
        $s = substr($der, $offset + 2, $sLength);

        // Pad R and S to 32 bytes each
        $r = str_pad(ltrim($r, "\x00"), 32, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), 32, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }
}
