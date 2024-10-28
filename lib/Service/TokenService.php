<?php
/**
 * @copyright Copyright (c) 2024 Julien Veyssier <julien-nc@posteo.net>
 *
 * @author Julien Veyssier <julien-nc@posteo.net>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

declare(strict_types=1);

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Exception\TokenExchangeFailedException;
use OCA\UserOIDC\Model\Token;
use OCA\UserOIDC\Vendor\Firebase\JWT\JWT;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\ISession;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;

class TokenService {

	private const SESSION_TOKEN_KEY = Application::APP_ID . '-user-token';

	private IClient $client;

	public function __construct(
		IClientService $clientService,
		private ISession $session,
		private LoggerInterface $logger,
		private ICrypto $crypto,
		private DiscoveryService $discoveryService,
		private ProviderMapper $providerMapper,
	) {
		$this->client = $clientService->newClient();
	}

	public function storeToken(array $tokenData): Token {
		$token = new Token($tokenData);
		$this->session->set(self::SESSION_TOKEN_KEY, json_encode($token, JSON_THROW_ON_ERROR));
		$this->logger->info('Store token', ['app' => Application::APP_ID]);
		return $token;
	}

	public function getToken(bool $refresh = true): ?Token {
		$sessionData = $this->session->get(self::SESSION_TOKEN_KEY);
		if (!$sessionData) {
			return null;
		}

		$token = new Token(json_decode($sessionData, true, 512, JSON_THROW_ON_ERROR));
		if ($token->isExpired()) {
			return $token;
		}

		if ($refresh && $token->isExpiring()) {
			$token = $this->refresh($token);
		}
		return $token;
	}

	public function refresh(Token $token) {
		$oidcProvider = $this->providerMapper->getProvider($token->getProviderId());
		$discovery = $this->discoveryService->obtainDiscovery($oidcProvider);

		try {
			$clientSecret = $oidcProvider->getClientSecret();
			if ($clientSecret !== '') {
				try {
					$clientSecret = $this->crypto->decrypt($clientSecret);
				} catch (\Exception $e) {
					$this->logger->error('Failed to decrypt oidc client secret', ['app' => Application::APP_ID]);
				}
			}
			$this->logger->debug('Refreshing the token: ' . $discovery['token_endpoint']);
			$result = $this->client->post(
				$discovery['token_endpoint'],
				[
					'body' => [
						'client_id' => $oidcProvider->getClientId(),
						'client_secret' => $clientSecret,
						'grant_type' => 'refresh_token',
						'refresh_token' => $token->getRefreshToken(),
					],
				]
			);
			$this->logger->debug('Token refresh request params', [
				'client_id' => $oidcProvider->getClientId(),
				'client_secret' => $clientSecret,
				'grant_type' => 'refresh_token',
				'refresh_token' => $token->getRefreshToken(),
			]);
			$body = $result->getBody();
			$bodyArray = json_decode(trim($body), true, 512, JSON_THROW_ON_ERROR);
			$this->logger->debug('Refresh token success: "' . trim($body) . '"', ['app' => Application::APP_ID]);
			return $this->storeToken(
				array_merge(
					$bodyArray,
					['provider_id' => $token->getProviderId()],
				)
			);
		} catch (\Exception $e) {
			$this->logger->error('Failed to refresh token ', ['exception' => $e, 'app' => Application::APP_ID]);
			// Failed to refresh, return old token which will be retried or otherwise timeout if expired
			return $token;
		}
	}

	public function decodeIdToken(Token $token): array {
		$provider = $this->providerMapper->getProvider($token->getProviderId());
		$jwks = $this->discoveryService->obtainJWK($provider, $token->getIdToken());
		JWT::$leeway = 60;
		$idTokenObject = JWT::decode($token->getIdToken(), $jwks);
		return json_decode(json_encode($idTokenObject), true);
	}

	public function getExchangedToken(string $targetAudience): Token {
		$loginToken = $this->getToken(true);
		$oidcProvider = $this->providerMapper->getProvider($loginToken->getProviderId());
		$discovery = $this->discoveryService->obtainDiscovery($oidcProvider);

		try {
			$clientSecret = $oidcProvider->getClientSecret();
			if ($clientSecret !== '') {
				try {
					$clientSecret = $this->crypto->decrypt($clientSecret);
				} catch (\Exception $e) {
					$this->logger->error('Failed to decrypt oidc client secret', ['app' => Application::APP_ID]);
				}
			}
			$this->logger->debug('Exchanging the token: ' . $discovery['token_endpoint']);
			// more in https://www.keycloak.org/securing-apps/token-exchange
			$result = $this->client->post(
				$discovery['token_endpoint'],
				[
					'body' => [
						'client_id' => $oidcProvider->getClientId(),
						'client_secret' => $clientSecret,
						'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
						'subject_token' => $loginToken->getAccessToken(),
						'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
						// can also be
						// urn:ietf:params:oauth:token-type:access_token
						// or urn:ietf:params:oauth:token-type:id_token
						// this one will get us an access token and refresh token within the response
						'requested_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
						'audience' => $targetAudience,
					],
				]
			);
			$this->logger->debug('Token refresh request params', [
				'client_id' => $oidcProvider->getClientId(),
				'client_secret' => $clientSecret,
				'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
				'subject_token' => $loginToken->getAccessToken(),
				'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
				'requested_token_type' => 'urn:ietf:params:oauth:token-type:refresh_token',
				'audience' => $targetAudience,
			]);
			$body = $result->getBody();
			$bodyArray = json_decode(trim($body), true, 512, JSON_THROW_ON_ERROR);
			$this->logger->debug('Token exchange success: "' . trim($body) . '"');
			$tokenData = array_merge(
				$bodyArray,
				['provider_id' => $loginToken->getProviderId()],
			);
			return new Token($tokenData);
		} catch (\Exception|\Throwable $e) {
			$this->logger->error('Failed to exchange token ', ['exception' => $e]);
			throw new TokenExchangeFailedException('Failed to exchange token', 0, $e);
		}
	}
}
