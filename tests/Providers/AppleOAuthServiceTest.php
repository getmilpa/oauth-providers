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

use Milpa\OAuth\DTO\AppleUserInfo;
use Milpa\OAuth\Providers\AppleOAuthService;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class AppleOAuthServiceTest extends TestCase
{
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * @return array{0: \OpenSSLAsymmetricKey, 1: string} [private key resource, PEM]
     */
    private function generateEs256KeyPair(): array
    {
        $resource = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        $this->assertNotFalse($resource, 'Test environment cannot generate EC keys (ext-openssl missing curve support)');

        openssl_pkey_export($resource, $pem);

        return [$resource, $pem];
    }

    public function testGetAuthUrlShape(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'dummy-key-only-needed-for-token-exchange');

        $url = $service->getAuthUrl('https://app.example.com/callback/apple');

        $this->assertStringStartsWith('https://appleid.apple.com/auth/authorize?', $url);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertSame([
            'client_id' => 'com.example.app',
            'redirect_uri' => 'https://app.example.com/callback/apple',
            'response_type' => 'code',
            'scope' => 'name email',
            'response_mode' => 'form_post',
        ], $params);
        $this->assertArrayNotHasKey('state', $params);
    }

    public function testGetAuthUrlIncludesStateWhenProvided(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'dummy-key-only-needed-for-token-exchange');

        $state = 'csrf-token-!@#$%^&*()_+ünïcödé';
        $url = $service->getAuthUrl('https://app.example.com/callback/apple', $state);

        [, $query] = explode('?', $url, 2);
        parse_str($query, $params);

        $this->assertArrayHasKey('state', $params);
        $this->assertSame($state, $params['state'], 'state must round-trip unmodified');
        $this->assertSame(1, substr_count($query, 'state='), 'state must appear exactly once in the query string');
    }

    public function testGetAuthUrlThrowsWhenNotConfigured(): void
    {
        $service = new AppleOAuthService('', '', '', '');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Apple Sign In not configured');

        $service->getAuthUrl('https://app.example.com/callback/apple');
    }

    /**
     * generateClientSecret() is private but is pure (no network) and holds
     * the entire ES256 JWT-signing responsibility — worth exercising directly
     * via reflection since exchangeCode() itself is not unit-testable (see
     * class docblock / package README friction notes on curl-bound methods).
     */
    public function testGenerateClientSecretProducesAStructurallyValidEs256Jwt(): void
    {
        [, $pem] = $this->generateEs256KeyPair();

        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', $pem);

        $method = (new ReflectionClass($service))->getMethod('generateClientSecret');
        $method->setAccessible(true);
        $jwt = $method->invoke($service);

        $parts = explode('.', $jwt);
        $this->assertCount(3, $parts, 'JWT must have header.claims.signature');

        $header = json_decode($this->base64UrlDecode($parts[0]), true);
        $this->assertSame(['alg' => 'ES256', 'kid' => 'KEYID1234'], $header);

        $claims = json_decode($this->base64UrlDecode($parts[1]), true);
        $this->assertSame('TEAMID1234', $claims['iss']);
        $this->assertSame('com.example.app', $claims['sub']);
        $this->assertSame('https://appleid.apple.com', $claims['aud']);
        $this->assertSame($claims['iat'] + 3600, $claims['exp']);

        // ES256 JWS signatures are the raw R+S concatenation, 32 bytes each.
        $signature = $this->base64UrlDecode($parts[2]);
        $this->assertSame(64, strlen($signature));
    }

    public function testGenerateClientSecretThrowsOnInvalidPrivateKey(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'not-a-valid-pem-key');

        $method = (new ReflectionClass($service))->getMethod('generateClientSecret');
        $method->setAccessible(true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Apple private key');

        $method->invoke($service);
    }

    /**
     * parseIdToken() is private and pure (string in, DTO out) — the part of
     * exchangeCode() that is honestly unit-testable without a live network call.
     */
    public function testParseIdTokenExtractsUserInfoFromJwtPayload(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'unused-for-this-method');

        $header = $this->base64UrlEncode(json_encode(['alg' => 'none'], JSON_THROW_ON_ERROR));
        $payload = $this->base64UrlEncode(json_encode([
            'sub' => '001234.abcd.5678',
            'email' => 'user@privaterelay.appleid.com',
        ], JSON_THROW_ON_ERROR));
        $idToken = "{$header}.{$payload}.unsigned";

        $method = (new ReflectionClass($service))->getMethod('parseIdToken');
        $method->setAccessible(true);

        /** @var AppleUserInfo $info */
        $info = $method->invoke($service, $idToken, 'Ada Lovelace');

        $this->assertSame('001234.abcd.5678', $info->id);
        $this->assertSame('user@privaterelay.appleid.com', $info->email);
        // Apple only sends the name in the POST body on the FIRST authorization;
        // it is never present in the id_token itself, so it's passed through as-is.
        $this->assertSame('Ada Lovelace', $info->name);
    }

    public function testParseIdTokenThrowsOnMalformedToken(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'unused-for-this-method');

        $method = (new ReflectionClass($service))->getMethod('parseIdToken');
        $method->setAccessible(true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Apple id_token format');

        $method->invoke($service, 'not-a-jwt', null);
    }

    public function testParseIdTokenThrowsWhenSubClaimMissing(): void
    {
        $service = new AppleOAuthService('com.example.app', 'TEAMID1234', 'KEYID1234', 'unused-for-this-method');

        $header = $this->base64UrlEncode(json_encode(['alg' => 'none'], JSON_THROW_ON_ERROR));
        $payload = $this->base64UrlEncode(json_encode(['email' => 'user@example.com'], JSON_THROW_ON_ERROR));
        $idToken = "{$header}.{$payload}.unsigned";

        $method = (new ReflectionClass($service))->getMethod('parseIdToken');
        $method->setAccessible(true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sub claim missing');

        $method->invoke($service, $idToken, null);
    }
}
