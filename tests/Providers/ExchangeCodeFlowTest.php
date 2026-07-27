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

namespace Milpa\OAuth\Tests\Providers;

use Milpa\OAuth\Providers\FacebookOAuthService;
use Milpa\OAuth\Providers\GitHubOAuthService;
use Milpa\OAuth\Providers\GitLabOAuthService;
use Milpa\OAuth\Providers\GoogleOAuthService;
use Milpa\OAuth\Providers\TwitchOAuthService;
use Milpa\OAuth\Tests\Fixtures\ScriptedTransport;
use PHPUnit\Framework\TestCase;

/**
 * The half of every provider that only runs once a real user has come back
 * from a real consent screen: exchanging the code, reading the profile, and
 * telling apart the four ways it can go wrong.
 *
 * Until the transport became a seam, none of it could be exercised without
 * talking to GitHub, GitLab, Google, Facebook and Twitch for real — so none of
 * it ever had been.
 */
final class ExchangeCodeFlowTest extends TestCase
{
    private const REDIRECT = 'https://app.example.test/callback';

    // ---- the happy path, per provider ------------------------------------------

    public function testGitHubReturnsTheProfileItWasGiven(): void
    {
        $http = ScriptedTransport::forFlow(
            ['access_token' => 'gho_abc'],
            ['id' => 4211, 'login' => 'rod', 'name' => 'Rodrigo', 'email' => 'rod@example.test', 'avatar_url' => 'https://a.test/r.png'],
        );

        $user = (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('code-1', self::REDIRECT);

        self::assertSame('4211', $user->id, 'The numeric id is carried as a string, the way every other provider gives it.');
        self::assertSame('rod', $user->login);
        self::assertSame('Rodrigo', $user->name);
        self::assertSame('rod@example.test', $user->email);
        self::assertSame('https://a.test/r.png', $user->avatarUrl);
    }

    public function testGitHubSendsTheCodeAndTheSecretToTheTokenEndpointAndThenTheTokenToTheApi(): void
    {
        // Both halves of the flow in one assertion: a provider that forgot the
        // redirect_uri, or that sent the code to the profile endpoint, would
        // still "work" against a fake that ignores its input.
        $http = ScriptedTransport::forFlow(['access_token' => 'gho_abc'], ['id' => 1, 'login' => 'rod']);

        (new GitHubOAuthService('mi-id', 'mi-secreto', $http))->exchangeCode('code-1', self::REDIRECT);

        self::assertCount(2, $http->calls);
        self::assertSame('POST', $http->calls[0]['method']);
        self::assertSame('code-1', $http->calls[0]['fields']['code']);
        self::assertSame('mi-id', $http->calls[0]['fields']['client_id']);
        self::assertSame('mi-secreto', $http->calls[0]['fields']['client_secret']);
        self::assertSame(self::REDIRECT, $http->calls[0]['fields']['redirect_uri']);
        self::assertSame('GET', $http->calls[1]['method']);
        self::assertContains('Authorization: Bearer gho_abc', $http->calls[1]['headers']);
    }

    public function testGitHubFallsBackToTheLoginWhenThereIsNoName(): void
    {
        // A GitHub account with no display name is ordinary. Leaving the name
        // empty would put a blank where the user's identity goes.
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['id' => 1, 'login' => 'rod']);

        $user = (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertSame('rod', $user->name);
        self::assertNull($user->email);
        self::assertNull($user->avatarUrl);
    }

    public function testGoogleReturnsTheProfileItWasGiven(): void
    {
        $http = ScriptedTransport::forFlow(
            ['access_token' => 'ya29.abc'],
            ['id' => '11', 'email' => 'rod@example.test', 'name' => 'Rodrigo', 'picture' => 'https://g.test/r.png'],
        );

        $user = (new GoogleOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertSame('11', $user->id);
        self::assertSame('rod@example.test', $user->email);
        self::assertSame('Rodrigo', $user->name);
        self::assertSame('https://g.test/r.png', $user->picture);
    }

    public function testGitLabReturnsTheProfileItWasGiven(): void
    {
        $http = ScriptedTransport::forFlow(
            ['access_token' => 'glpat'],
            ['id' => 77, 'username' => 'rod', 'name' => 'Rodrigo', 'email' => 'rod@example.test'],
        );

        $user = (new GitLabOAuthService('id', 'secret', '', $http))->exchangeCode('c', self::REDIRECT);

        self::assertSame('77', $user->id);
        self::assertSame('rod', $user->username);
    }

    public function testGitLabTalksToTheSelfHostedInstanceItWasConfiguredWith(): void
    {
        // The whole point of the instance URL: a company GitLab is not
        // gitlab.com, and sending its users' codes there would leak them.
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['id' => 1, 'username' => 'rod']);

        (new GitLabOAuthService('id', 'secret', 'https://gitlab.empresa.test/', $http))
            ->exchangeCode('c', self::REDIRECT);

        self::assertSame('https://gitlab.empresa.test/oauth/token', $http->calls[0]['url']);
        self::assertSame('https://gitlab.empresa.test/api/v4/user', $http->calls[1]['url'], 'And no double slash from the trailing one.');
    }

    public function testTwitchReadsTheProfileOutOfItsDataEnvelope(): void
    {
        // Twitch wraps the user in a `data` array of one. Reading it as a flat
        // object would look like an incomplete profile.
        $http = ScriptedTransport::forFlow(
            ['access_token' => 't'],
            ['data' => [['id' => '9', 'login' => 'rod', 'display_name' => 'Rod', 'email' => 'rod@example.test']]],
        );

        $user = (new TwitchOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertSame('9', $user->id);
        self::assertSame('rod', $user->login);
        self::assertSame('Rod', $user->displayName);
    }

    public function testTwitchIdentifiesTheApplicationOnTheProfileCall(): void
    {
        // Twitch rejects a profile request that carries a token but no
        // Client-Id. It is the one provider here that needs both.
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['data' => [['id' => '9', 'login' => 'rod']]]);

        (new TwitchOAuthService('mi-id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertContains('Client-Id: mi-id', $http->calls[1]['headers']);
    }

    public function testFacebookReadsThePictureOutOfItsNestedEnvelope(): void
    {
        $http = ScriptedTransport::forFlow(
            ['access_token' => 't'],
            ['id' => '5', 'name' => 'Rodrigo', 'email' => 'rod@example.test', 'picture' => ['data' => ['url' => 'https://f.test/r.png']]],
        );

        $user = (new FacebookOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertSame('5', $user->id);
        self::assertSame('https://f.test/r.png', $user->picture);
    }

    public function testFacebookSurvivesAProfileWithNoPictureAtAll(): void
    {
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['id' => '5', 'name' => 'Rodrigo']);

        $user = (new FacebookOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);

        self::assertNull($user->picture);
        self::assertNull($user->email);
    }

    // ---- the four ways it goes wrong ------------------------------------------------

    public function testATokenEndpointThatRefusesIsReportedWithWhatItSaid(): void
    {
        // The body is the only thing that says WHY — a bad secret and an
        // expired code look identical without it.
        $http = ScriptedTransport::answering(401, 'bad_verification_code');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitHub token exchange failed: bad_verification_code');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testATokenEndpointThatCouldNotBeReachedAtAllSaysSo(): void
    {
        // Status 0 is "no answer", not "the provider said no". Quoting an empty
        // body would make the message end in a colon and nothing.
        $http = ScriptedTransport::answering(0);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitHub token exchange failed: no response');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testAnErrorInsideATwoHundredIsStillAnError(): void
    {
        // GitHub answers 200 with an `error` field for a bad code. Trusting the
        // status alone would carry on to the profile call with no token.
        $http = ScriptedTransport::answering(200, ['error' => 'bad_verification_code']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitHub token error: bad_verification_code');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testGitLabPrefersTheLongErrorDescriptionWhenThereIsOne(): void
    {
        $http = ScriptedTransport::answering(200, [
            'error' => 'invalid_grant',
            'error_description' => 'The provided authorization grant is invalid',
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('GitLab token error: The provided authorization grant is invalid');

        (new GitLabOAuthService('id', 'secret', '', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testAnAnswerWithNoTokenInItIsRefusedBeforeTheProfileCall(): void
    {
        $http = ScriptedTransport::answering(200, ['scope' => 'read:user']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('access_token missing in GitHub response');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testAProfileEndpointThatRefusesIsReportedSeparately(): void
    {
        // The token was fine; the profile call was not. Reporting this as a
        // token failure would send someone to check the wrong credentials.
        $http = new ScriptedTransport([
            ['status' => 200, 'body' => (string) json_encode(['access_token' => 't'])],
            ['status' => 500, 'body' => 'boom'],
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to fetch GitHub user info');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testAProfileMissingWhatIdentifiesTheUserIsRefused(): void
    {
        // No id means nothing to key an account on. Accepting it would create a
        // user the next login could not find again.
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['name' => 'Rodrigo']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Incomplete user data from GitHub');

        (new GitHubOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testTwitchRefusesAnEmptyDataEnvelope(): void
    {
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['data' => []]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Incomplete user data from Twitch');

        (new TwitchOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testAnUnconfiguredProviderRefusesBeforeMakingAnyCallAtAll(): void
    {
        // Sending an empty client_id to the provider gets an opaque 401 back;
        // refusing here names the two environment variables to set.
        $http = ScriptedTransport::forFlow(['access_token' => 't'], ['id' => 1, 'login' => 'rod']);

        try {
            (new GitHubOAuthService('', '', $http))->exchangeCode('c', self::REDIRECT);
            self::fail('Expected the unconfigured provider to refuse.');
        } catch (\RuntimeException $e) {
            self::assertStringContainsString('GITHUB_CLIENT_ID', $e->getMessage());
            self::assertSame([], $http->calls, 'Nothing was sent anywhere.');
        }
    }

    // ---- the same five failures, on every provider ----------------------------------

    /**
     * A host wires several of these at once. When one of them fails, the
     * message has to name WHICH — five providers whose errors read alike are
     * five providers nobody can debug apart.
     *
     * @return iterable<string, array{string, callable(ScriptedTransport): object, array<string, mixed>}>
     */
    public static function providers(): iterable
    {
        yield 'GitHub' => [
            'GitHub',
            static fn (ScriptedTransport $http): object => new GitHubOAuthService('id', 'secret', $http),
            ['name' => 'sin id ni login'],
        ];
        yield 'GitLab' => [
            'GitLab',
            static fn (ScriptedTransport $http): object => new GitLabOAuthService('id', 'secret', '', $http),
            ['name' => 'sin id ni username'],
        ];
        yield 'Google' => [
            'Google',
            static fn (ScriptedTransport $http): object => new GoogleOAuthService('id', 'secret', $http),
            ['name' => 'sin id ni email'],
        ];
        yield 'Facebook' => [
            'Facebook',
            static fn (ScriptedTransport $http): object => new FacebookOAuthService('id', 'secret', $http),
            ['email' => 'sin id ni nombre'],
        ];
        yield 'Twitch' => [
            'Twitch',
            static fn (ScriptedTransport $http): object => new TwitchOAuthService('id', 'secret', $http),
            ['data' => []],
        ];
    }

    /**
     * @param callable(ScriptedTransport): object $build
     * @param array<string, mixed>                $incompleteProfile
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providers')]
    public function testARefusedTokenExchangeNamesItsProvider(string $name, callable $build, array $incompleteProfile): void
    {
        $service = $build(ScriptedTransport::answering(401, 'nope'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage($name . ' token exchange failed: nope');

        $service->exchangeCode('c', self::REDIRECT);
    }

    /**
     * @param callable(ScriptedTransport): object $build
     * @param array<string, mixed>                $incompleteProfile
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providers')]
    public function testAnUnreachableTokenEndpointNamesItsProvider(string $name, callable $build, array $incompleteProfile): void
    {
        $service = $build(ScriptedTransport::answering(0));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage($name . ' token exchange failed: no response');

        $service->exchangeCode('c', self::REDIRECT);
    }

    /**
     * @param callable(ScriptedTransport): object $build
     * @param array<string, mixed>                $incompleteProfile
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providers')]
    public function testAnAnswerWithoutATokenNamesItsProvider(string $name, callable $build, array $incompleteProfile): void
    {
        $service = $build(ScriptedTransport::answering(200, ['scope' => 'basic']));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('access_token missing in ' . $name . ' response');

        $service->exchangeCode('c', self::REDIRECT);
    }

    /**
     * @param callable(ScriptedTransport): object $build
     * @param array<string, mixed>                $incompleteProfile
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providers')]
    public function testARefusedProfileCallNamesItsProvider(string $name, callable $build, array $incompleteProfile): void
    {
        $service = $build(new ScriptedTransport([
            ['status' => 200, 'body' => (string) json_encode(['access_token' => 't'])],
            ['status' => 500, 'body' => 'boom'],
        ]));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to fetch ' . $name . ' user info');

        $service->exchangeCode('c', self::REDIRECT);
    }

    /**
     * @param callable(ScriptedTransport): object $build
     * @param array<string, mixed>                $incompleteProfile
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('providers')]
    public function testAProfileMissingItsIdentityNamesItsProvider(string $name, callable $build, array $incompleteProfile): void
    {
        $service = $build(ScriptedTransport::forFlow(['access_token' => 't'], $incompleteProfile));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Incomplete user data from ' . $name);

        $service->exchangeCode('c', self::REDIRECT);
    }

    public function testFacebookQuotesTheMessageInsideItsNestedErrorEnvelope(): void
    {
        // Facebook nests the reason two levels down. Reading it flat would
        // report every one of its refusals as "unknown".
        $http = ScriptedTransport::answering(200, ['error' => ['message' => 'This authorization code has expired']]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Facebook token error: This authorization code has expired');

        (new FacebookOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testFacebookSaysUnknownWhenItsErrorEnvelopeCarriesNoMessage(): void
    {
        $http = ScriptedTransport::answering(200, ['error' => ['code' => 190]]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Facebook token error: unknown');

        (new FacebookOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }

    public function testTwitchQuotesItsOwnErrorField(): void
    {
        $http = ScriptedTransport::answering(200, ['message' => 'invalid client secret']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Twitch token error: invalid client secret');

        (new TwitchOAuthService('id', 'secret', $http))->exchangeCode('c', self::REDIRECT);
    }
}
