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
 * Immutable DTO with user info returned by GitLab OAuth.
 */
final readonly class GitLabUserInfo
{
    public function __construct(
        public string $id,
        public string $username,
        public string $name,
        public ?string $email = null,
        public ?string $avatarUrl = null
    ) {
    }

    /**
     * Convert to a plain array using GitLab API field names (snake_case avatar_url).
     *
     * @return array{id: string, username: string, name: string, email: ?string, avatar_url: ?string}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'name' => $this->name,
            'email' => $this->email,
            'avatar_url' => $this->avatarUrl,
        ];
    }
}
