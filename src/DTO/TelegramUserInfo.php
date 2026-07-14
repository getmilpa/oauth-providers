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

namespace Milpa\OAuth\DTO;

/**
 * Immutable DTO with user info returned by Telegram Login Widget.
 */
final readonly class TelegramUserInfo
{
    public function __construct(
        public string $id,
        public string $firstName,
        public ?string $lastName = null,
        public ?string $username = null,
        public ?string $photoUrl = null
    ) {
    }

    /**
     * Join first and last name into one display string, trimming when the last name is absent.
     */
    public function getFullName(): string
    {
        return trim($this->firstName . ' ' . ($this->lastName ?? ''));
    }

    /**
     * Convert to a plain array using Telegram Login Widget field names (snake_case).
     *
     * @return array{id: string, first_name: string, last_name: ?string, username: ?string, photo_url: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'first_name' => $this->firstName,
            'last_name' => $this->lastName,
            'username' => $this->username,
            'photo_url' => $this->photoUrl,
        ];
    }
}
