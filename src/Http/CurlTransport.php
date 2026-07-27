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
 * The default transport: cURL, exactly as every provider in this package
 * called it inline before there was a seam.
 *
 * It is the default so that a host wiring a provider with nothing but its
 * client id and secret keeps working unchanged, and this package keeps its
 * empty `require` block — no PSR-18 client to supply, no dependency added.
 */
final class CurlTransport implements HttpTransportInterface
{
    /**
     * POSTs `$fields` as `application/x-www-form-urlencoded`.
     *
     * @param array<string, string> $fields
     * @param list<string>          $headers
     *
     * @return array{status: int, body: string}
     */
    public function post(string $url, array $fields, array $headers = []): array
    {
        return $this->send($url, $headers, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields),
        ]);
    }

    /**
     * GETs `$url`.
     *
     * @param list<string> $headers
     *
     * @return array{status: int, body: string}
     */
    public function get(string $url, array $headers = []): array
    {
        return $this->send($url, $headers, []);
    }

    /**
     * @param list<string>      $headers
     * @param array<int, mixed> $options
     *
     * @return array{status: int, body: string}
     */
    private function send(string $url, array $headers, array $options): array
    {
        $handle = curl_init($url);
        if ($handle === false) {
            return ['status' => 0, 'body' => ''];
        }

        curl_setopt_array($handle, $options + [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
        ]);

        $response = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        // A request that could never be made is not a 0-status answer from the
        // provider — it is no answer, and the caller must be able to tell.
        if (!is_string($response)) {
            return ['status' => 0, 'body' => ''];
        }

        return ['status' => $status, 'body' => $response];
    }
}
