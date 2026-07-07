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
 * Immutable DTO with user info returned by Facebook OAuth.
 */
final readonly class FacebookUserInfo
{
    public function __construct(
        public string $id,
        public string $name,
        public ?string $email = null,
        public ?string $picture = null
    ) {
    }

    /**
     * Convert to a plain array using Facebook Graph API field names.
     *
     * @return array{id: string, name: string, email: ?string, picture: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'picture' => $this->picture,
        ];
    }
}
