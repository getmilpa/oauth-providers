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

namespace Milpa\OAuth\Tests\Fixtures;

use Milpa\OAuth\Http\HttpTransportInterface;

/**
 * A transport that answers from a script and records what it was asked.
 *
 * Every provider makes the same two calls in the same order — POST the code,
 * GET the profile — so a list of two answers is the whole conversation.
 */
final class ScriptedTransport implements HttpTransportInterface
{
    /** @var list<array{method: string, url: string, fields: array<string, string>, headers: list<string>}> */
    public array $calls = [];

    /** @var list<array{status: int, body: string}> */
    private array $answers;

    /**
     * @param list<array{status: int, body: string}> $answers Delivered in order, one per call.
     */
    public function __construct(array $answers)
    {
        $this->answers = $answers;
    }

    /**
     * A pair of answers for the usual flow: the token, then the profile.
     *
     * @param array<string, mixed> $token
     * @param array<string, mixed> $profile
     */
    public static function forFlow(array $token, array $profile): self
    {
        return new self([
            ['status' => 200, 'body' => (string) json_encode($token)],
            ['status' => 200, 'body' => (string) json_encode($profile)],
        ]);
    }

    /**
     * A single answer, for the call that is expected to fail first.
     *
     * @param array<string, mixed>|string $body
     */
    public static function answering(int $status, array|string $body = ''): self
    {
        return new self([[
            'status' => $status,
            'body' => is_string($body) ? $body : (string) json_encode($body),
        ]]);
    }

    public function post(string $url, array $fields, array $headers = []): array
    {
        $this->calls[] = ['method' => 'POST', 'url' => $url, 'fields' => $fields, 'headers' => $headers];

        return $this->next();
    }

    public function get(string $url, array $headers = []): array
    {
        $this->calls[] = ['method' => 'GET', 'url' => $url, 'fields' => [], 'headers' => $headers];

        return $this->next();
    }

    /**
     * @return array{status: int, body: string}
     */
    private function next(): array
    {
        // Running out of script means the provider made a call the test did not
        // expect. Answering 0 makes that show up as "no answer" rather than as
        // a silent success.
        return array_shift($this->answers) ?? ['status' => 0, 'body' => ''];
    }
}
