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
 * Immutable DTO with user info returned by Google OAuth.
 */
final readonly class GoogleUserInfo
{
    public function __construct(
        public string $id,
        public string $email,
        public string $name,
        public ?string $picture = null
    ) {
    }

    /**
     * Convert to a plain array using Google's userinfo endpoint field names.
     *
     * @return array{id: string, email: string, name: string, picture: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            'picture' => $this->picture,
        ];
    }
}
