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

use Milpa\OAuth\Providers\TelegramAuthService;
use PHPUnit\Framework\TestCase;

/**
 * TelegramAuthService::verify() is the one provider entry point that is pure
 * HMAC verification with no network call — fully unit-testable, unlike the
 * curl-bound exchangeCode()/getAuthUrl() paths of the other six providers.
 */
class TelegramAuthServiceTest extends TestCase
{
    private const BOT_TOKEN = '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11';

    /**
     * Recreate the widget payload + HMAC hash exactly as Telegram's docs
     * (and TelegramAuthService::verify()) compute it, so we can build valid
     * fixtures without a live Telegram callback.
     *
     * @param array<string, int|string> $data Payload without `hash`
     *
     * @return array<string, int|string> Payload with a valid `hash` appended
     */
    private function signPayload(array $data, string $botToken = self::BOT_TOKEN): array
    {
        $checkData = $data;
        ksort($checkData);
        $parts = [];
        foreach ($checkData as $key => $value) {
            $parts[] = "{$key}={$value}";
        }
        $dataCheckString = implode("\n", $parts);

        $secretKey = hash('sha256', $botToken, true);
        $data['hash'] = hash_hmac('sha256', $dataCheckString, $secretKey);

        return $data;
    }

    public function testVerifyAcceptsCorrectlySignedPayload(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $payload = $this->signPayload([
            'id' => 123456789,
            'first_name' => 'Ada',
            'last_name' => 'Lovelace',
            'username' => 'ada_l',
            'photo_url' => 'https://t.me/i/userpic/320/ada.jpg',
            'auth_date' => time(),
        ]);

        $info = $service->verify($payload);

        $this->assertSame('123456789', $info->id);
        $this->assertSame('Ada', $info->firstName);
        $this->assertSame('Lovelace', $info->lastName);
        $this->assertSame('ada_l', $info->username);
    }

    public function testVerifyDefaultsFirstNameWhenMissingFromPayload(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $payload = $this->signPayload([
            'id' => 1,
            'auth_date' => time(),
        ]);

        $info = $service->verify($payload);

        $this->assertSame('User', $info->firstName);
    }

    public function testVerifyRejectsTamperedHash(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $payload = $this->signPayload(['id' => 1, 'first_name' => 'Ada', 'auth_date' => time()]);
        $payload['first_name'] = 'Eve'; // tamper after signing

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Telegram auth signature');

        $service->verify($payload);
    }

    public function testVerifyRejectsSignatureFromWrongBotToken(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $payload = $this->signPayload(
            ['id' => 1, 'first_name' => 'Ada', 'auth_date' => time()],
            botToken: 'different-bot-token'
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid Telegram auth signature');

        $service->verify($payload);
    }

    public function testVerifyRejectsExpiredAuthDate(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $payload = $this->signPayload([
            'id' => 1,
            'first_name' => 'Ada',
            'auth_date' => time() - 90000, // > 24h AUTH_WINDOW_SECONDS
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Telegram auth data expired');

        $service->verify($payload);
    }

    public function testVerifyRejectsMissingRequiredFields(): void
    {
        $service = new TelegramAuthService(self::BOT_TOKEN);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Missing required Telegram auth fields');

        $service->verify(['first_name' => 'Ada']);
    }

    public function testVerifyThrowsWhenNotConfigured(): void
    {
        $service = new TelegramAuthService('');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Telegram auth not configured');

        $service->verify(['id' => 1, 'auth_date' => time(), 'hash' => 'x']);
    }
}
