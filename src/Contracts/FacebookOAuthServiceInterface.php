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

namespace Milpa\OAuth\Contracts;

use Milpa\OAuth\DTO\FacebookUserInfo;

/**
 * Contract for Facebook OAuth operations.
 *
 * Each consumer plugin provides its own redirectUri to support
 * independent callback routes per plugin.
 */
interface FacebookOAuthServiceInterface
{
    /**
     * Build the Facebook authorization URL.
     *
     * @param string      $redirectUri Callback URL specific to the consumer plugin
     * @param string|null $state       Opaque CSRF-protection value. When given, it is
     *                                 appended to the URL as-is and Facebook echoes it
     *                                 back unmodified on the query string of the
     *                                 callback request. Generating, storing, and
     *                                 verifying it is entirely the caller's
     *                                 responsibility — this provider only transports it.
     */
    public function getAuthUrl(string $redirectUri, ?string $state = null): string;

    /**
     * Exchange authorization code for user info.
     *
     * @param string $code        Authorization code from Facebook callback
     * @param string $redirectUri Must match the one used in getAuthUrl()
     */
    public function exchangeCode(string $code, string $redirectUri): FacebookUserInfo;
}
