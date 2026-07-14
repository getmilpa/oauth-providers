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

use Milpa\OAuth\DTO\TelegramUserInfo;
use Milpa\OAuth\Contracts\TelegramAuthServiceInterface;

/**
 * Telegram Login Widget verification.
 *
 * Validates HMAC signature of widget data using the bot token.
 */
class TelegramAuthService implements TelegramAuthServiceInterface
{
    private const AUTH_WINDOW_SECONDS = 86400; // 24 hours

    public function __construct(
        private readonly string $botToken
    ) {
    }

    /**
     * Verify the HMAC-SHA-256 signature of Telegram Login Widget data and reject
     * payloads older than the 24-hour auth window.
     */
    public function verify(array $data): TelegramUserInfo
    {
        if (empty($this->botToken)) {
            throw new \RuntimeException('Telegram auth not configured: TELEGRAM_BOT_TOKEN is required');
        }

        if (!isset($data['id'], $data['auth_date'], $data['hash'])) {
            throw new \RuntimeException('Missing required Telegram auth fields');
        }

        $authDate = (int) $data['auth_date'];
        if (time() - $authDate > self::AUTH_WINDOW_SECONDS) {
            throw new \RuntimeException('Telegram auth data expired');
        }

        $checkHash = $data['hash'];
        $checkData = $data;
        unset($checkData['hash']);

        ksort($checkData);
        $parts = [];
        foreach ($checkData as $key => $value) {
            $parts[] = "{$key}={$value}";
        }
        $dataCheckString = implode("\n", $parts);

        $secretKey = hash('sha256', $this->botToken, true);
        $calculatedHash = hash_hmac('sha256', $dataCheckString, $secretKey);

        if (!hash_equals($calculatedHash, $checkHash)) {
            throw new \RuntimeException('Invalid Telegram auth signature');
        }

        return new TelegramUserInfo(
            id: (string) $data['id'],
            firstName: $data['first_name'] ?? 'User',
            lastName: $data['last_name'] ?? null,
            username: $data['username'] ?? null,
            photoUrl: $data['photo_url'] ?? null
        );
    }
}
