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

namespace Milpa\OAuth\Contracts;

use Milpa\OAuth\DTO\TelegramUserInfo;

/**
 * Contract for Telegram Login Widget verification.
 */
interface TelegramAuthServiceInterface
{
    /**
     * Verify and extract user info from Telegram Login Widget data.
     *
     * @param array<string, mixed> $data Raw data from Telegram widget
     *
     * @return TelegramUserInfo Verified user info
     *
     * @throws \RuntimeException If verification fails
     */
    public function verify(array $data): TelegramUserInfo;
}
