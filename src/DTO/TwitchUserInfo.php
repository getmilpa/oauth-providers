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

namespace Milpa\OAuth\DTO;

/**
 * Immutable DTO with user info returned by Twitch OAuth.
 */
final readonly class TwitchUserInfo
{
    public function __construct(
        public string $id,
        public string $login,
        public string $displayName,
        public ?string $email = null,
        public ?string $profileImageUrl = null
    ) {
    }

    /**
     * Convert to a plain array using Twitch Helix API field names (snake_case).
     *
     * @return array{id: string, login: string, display_name: string, email: ?string, profile_image_url: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'login' => $this->login,
            'display_name' => $this->displayName,
            'email' => $this->email,
            'profile_image_url' => $this->profileImageUrl,
        ];
    }
}
