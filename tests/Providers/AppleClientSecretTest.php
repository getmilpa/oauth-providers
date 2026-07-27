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

use Milpa\OAuth\Providers\AppleOAuthService;
use Milpa\OAuth\Tests\Fixtures\ScriptedTransport;
use PHPUnit\Framework\TestCase;

/**
 * Apple is the odd one out: its `client_secret` is not a secret at all, it is a
 * short-lived ES256 JWT this package has to mint and sign on every exchange.
 *
 * Nothing had ever run that signing. A key it cannot read, a signature it lays
 * out wrong, a DER-to-raw conversion off by a byte — every one of those fails
 * only at Apple's endpoint, as an opaque `invalid_client`, in production.
 */
final class AppleClientSecretTest extends TestCase
{
    private const REDIRECT = 'https://app.example.test/callback';

    /**
     * A real EC P-256 private key, generated for this test — the curve Apple
     * requires for ES256.
     */
    private function privateKey(): string
    {
        $key = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        self::assertNotFalse($key, 'The test needs a real EC key; openssl could not make one.');

        $pem = '';
        self::assertTrue(openssl_pkey_export($key, $pem));

        return $pem;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function idToken(array $claims): string
    {
        $encode = static fn (array $part): string => rtrim(strtr(base64_encode((string) json_encode($part)), '+/', '-_'), '=');

        return $encode(['alg' => 'RS256']) . '.' . $encode($claims) . '.firma-que-no-se-verifica';
    }

    public function testAnExchangeSignsAClientSecretAndReturnsTheUserBehindTheIdToken(): void
    {
        $http = ScriptedTransport::answering(200, [
            'id_token' => $this->idToken(['sub' => '001234.abc', 'email' => 'rod@privaterelay.appleid.com']),
        ]);

        $user = (new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http))
            ->exchangeCode('code-1', self::REDIRECT);

        self::assertSame('001234.abc', $user->id);
        self::assertSame('rod@privaterelay.appleid.com', $user->email);
        self::assertNull($user->name, 'Apple only sends the name on the very first authorization.');
    }

    public function testTheNameApplePassesOnlyOnceIsCarriedThrough(): void
    {
        // Apple sends the display name in the form post of the FIRST consent
        // and never again. If the caller hands it over, it has to survive.
        $http = ScriptedTransport::answering(200, ['id_token' => $this->idToken(['sub' => '001234.abc'])]);

        $user = (new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http))
            ->exchangeCode('code-1', self::REDIRECT, 'Rodrigo Vicente');

        self::assertSame('Rodrigo Vicente', $user->name);
        self::assertNull($user->email);
    }

    public function testTheSignedSecretIsAThreePartJwtNamingTheKeyAndTheTeam(): void
    {
        // Apple reads the key id out of the header and the team out of the
        // claims. A secret that omits either is rejected as invalid_client
        // with nothing to go on.
        $http = ScriptedTransport::answering(200, ['id_token' => $this->idToken(['sub' => '1'])]);

        (new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http))
            ->exchangeCode('code-1', self::REDIRECT);

        $secret = $http->calls[0]['fields']['client_secret'];
        $parts = explode('.', $secret);

        self::assertCount(3, $parts, 'A JWT is header, claims and signature.');

        $decode = static fn (string $part): array => (array) json_decode(
            (string) base64_decode(strtr($part, '-_', '+/'), true),
            true,
        );

        self::assertSame(['alg' => 'ES256', 'kid' => 'KEY123'], $decode($parts[0]));

        $claims = $decode($parts[1]);
        self::assertSame('TEAM123', $claims['iss']);
        self::assertSame('com.example.app', $claims['sub']);
        self::assertSame('https://appleid.apple.com', $claims['aud']);
        self::assertSame($claims['iat'] + 3600, $claims['exp'], 'Short-lived, the way Apple asks.');
    }

    public function testTheSignatureIsTheSixtyFourBytesEs256Requires(): void
    {
        // openssl hands back a DER structure; ES256 wants raw R+S, 32 bytes
        // each. Sending the DER bytes is the classic Apple Sign In bug and it
        // only shows up as a rejection from Apple.
        $http = ScriptedTransport::answering(200, ['id_token' => $this->idToken(['sub' => '1'])]);

        (new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http))
            ->exchangeCode('code-1', self::REDIRECT);

        $parts = explode('.', $http->calls[0]['fields']['client_secret']);
        $signature = base64_decode(strtr($parts[2], '-_', '+/'), true);

        self::assertNotFalse($signature);
        self::assertSame(64, \strlen($signature));
    }

    public function testAKeyOpensslCannotReadIsRefusedByName(): void
    {
        $http = ScriptedTransport::answering(200, ['id_token' => $this->idToken(['sub' => '1'])]);
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', 'no soy una llave', $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Apple private key');

        $service->exchangeCode('code-1', self::REDIRECT);
    }

    public function testARefusedTokenExchangeIsReportedWithWhatAppleSaid(): void
    {
        $http = ScriptedTransport::answering(400, 'invalid_client');
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Apple token exchange failed: invalid_client');

        $service->exchangeCode('code-1', self::REDIRECT);
    }

    public function testAnErrorInsideATwoHundredIsStillAnError(): void
    {
        $http = ScriptedTransport::answering(200, ['error' => 'invalid_grant']);
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Apple token error: invalid_grant');

        $service->exchangeCode('code-1', self::REDIRECT);
    }

    public function testAnAnswerWithNoIdTokenIsRefused(): void
    {
        $http = ScriptedTransport::answering(200, ['access_token' => 'no-sirve-aqui']);
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('id_token missing in Apple response');

        $service->exchangeCode('code-1', self::REDIRECT);
    }

    public function testSomethingThatIsNotAJwtIsRefusedBeforeItIsDecoded(): void
    {
        $http = ScriptedTransport::answering(200, ['id_token' => 'no.es-un-jwt']);
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Apple id_token format');

        $service->exchangeCode('code-1', self::REDIRECT);
    }

    public function testAnIdTokenWithNoSubjectIsRefused(): void
    {
        // `sub` is Apple's stable user id. Without it there is nothing to key
        // an account on, and the next sign-in would look like a new person.
        $http = ScriptedTransport::answering(200, ['id_token' => $this->idToken(['email' => 'rod@example.test'])]);
        $service = new AppleOAuthService('com.example.app', 'TEAM123', 'KEY123', $this->privateKey(), $http);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('sub claim missing in Apple id_token');

        $service->exchangeCode('code-1', self::REDIRECT);
    }
}
