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
 * Immutable DTO with user info returned by GitHub OAuth.
 */
final readonly class GitHubUserInfo
{
    public function __construct(
        public string $id,
        public string $login,
        public string $name,
        public ?string $email = null,
        public ?string $avatarUrl = null
    ) {
    }

    /**
     * Convert to a plain array using GitHub REST API field names (snake_case avatar_url).
     *
     * @return array{id: string, login: string, name: string, email: ?string, avatar_url: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'login' => $this->login,
            'name' => $this->name,
            'email' => $this->email,
            'avatar_url' => $this->avatarUrl,
        ];
    }
}
