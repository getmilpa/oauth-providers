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

namespace Milpa\OAuth\Http;

/**
 * The two HTTP calls every OAuth 2.0 authorization-code flow makes: POST the
 * code to the token endpoint, GET the profile with the token that comes back.
 *
 * It exists as a seam. Every provider in this package used to call `curl_*`
 * inline, which meant the half of each one that matters — how a token error is
 * told apart from a transport error, what a half-filled profile does, which
 * field stands in when the optional one is absent — could not be exercised
 * without talking to GitHub, Google, Apple and the rest for real.
 */
interface HttpTransportInterface
{
    /**
     * POSTs `$fields` as `application/x-www-form-urlencoded`.
     *
     * @param array<string, string> $fields
     * @param list<string>          $headers In `Name: value` form.
     *
     * @return array{status: int, body: string} `status` is 0 when the request could not be made at all.
     */
    public function post(string $url, array $fields, array $headers = []): array;

    /**
     * GETs `$url`, typically the profile endpoint with the token in a header.
     *
     * @param list<string> $headers In `Name: value` form.
     *
     * @return array{status: int, body: string} `status` is 0 when the request could not be made at all.
     */
    public function get(string $url, array $headers = []): array;
}
