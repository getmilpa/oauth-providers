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

use Milpa\OAuth\DTO\AppleUserInfo;

/**
 * Contract for Apple Sign In operations.
 *
 * Apple uses OAuth 2.0 with JWT-based client secrets and returns
 * user info inside the id_token (not a separate userinfo endpoint).
 *
 * IMPORTANT: Apple only sends the user's name on the FIRST authorization.
 * Consumer plugins must persist the name on first login.
 *
 * Each consumer plugin provides its own redirectUri.
 */
interface AppleOAuthServiceInterface
{
    /**
     * Build the Apple authorization URL.
     *
     * @param string      $redirectUri Callback URL specific to the consumer plugin
     * @param string|null $state       Opaque CSRF-protection value. When given, it is
     *                                 appended to the URL as-is and Apple echoes it
     *                                 back unmodified in the form_post callback body.
     *                                 Generating, storing, and verifying it is
     *                                 entirely the caller's responsibility — this
     *                                 provider only transports it.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string;

    /**
     * Exchange authorization code for user info.
     *
     * @param string      $code        Authorization code from Apple callback
     * @param string      $redirectUri Must match the one used in getAuthUrl()
     * @param string|null $userName    User's name from the POST body (only on first auth)
     */
    public function exchangeCode(string $code, string $redirectUri, ?string $userName = null): AppleUserInfo;
}
