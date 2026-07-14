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
 * Immutable DTO with user info returned by Apple Sign In.
 *
 * Apple only sends the user's name on the FIRST authorization.
 * Subsequent logins only return the `sub` (id) and email from the id_token.
 */
final readonly class AppleUserInfo
{
    public function __construct(
        public string $id,
        public ?string $email = null,
        public ?string $name = null
    ) {
    }

    /**
     * Convert to a plain array using Apple's id_token claim names.
     *
     * @return array{id: string, email: ?string, name: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
        ];
    }
}
