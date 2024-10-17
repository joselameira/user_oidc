<?php
/**
 * @copyright Copyright (c) 2023 Julien Veyssier <eneiluj@posteo.net>
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

namespace OCA\UserOIDC\Controller;

use OCA\UserOIDC\AppInfo\Application;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\IRequest;

class BaseOidcController extends Controller {

	public function __construct(
		IRequest $request,
		private IConfig $config,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * @return bool
	 */
	protected function isDebugModeEnabled(): bool {
		return $this->config->getSystemValueBool('debug', false);
	}

	/**
	 * @param string $message
	 * @param int $statusCode
	 * @param array $throttleMetadata
	 * @param bool|null $throttle
	 * @return TemplateResponse
	 */
	protected function buildErrorTemplateResponse(string $message, int $statusCode, array $throttleMetadata = [], ?bool $throttle = null): TemplateResponse {
		$params = [
			'errors' => [
				['error' => $message],
			],
		];
		return $this->buildFailureTemplateResponse('', 'error', $params, $statusCode, $throttleMetadata, $throttle);
	}

	/**
	 * @param string $message
	 * @param int $statusCode
	 * @param array $throttleMetadata
	 * @param bool|null $throttle
	 * @return TemplateResponse
	 */
	protected function build403TemplateResponse(string $message, int $statusCode, array $throttleMetadata = [], ?bool $throttle = null): TemplateResponse {
		$params = ['message' => $message];
		return $this->buildFailureTemplateResponse('core', '403', $params, $statusCode, $throttleMetadata, $throttle);
	}

	/**
	 * @param string $appName
	 * @param string $templateName
	 * @param array $params
	 * @param int $statusCode
	 * @param array $throttleMetadata
	 * @param bool|null $throttle
	 * @return TemplateResponse
	 */
	protected function buildFailureTemplateResponse(string $appName, string $templateName, array $params, int $statusCode,
		array $throttleMetadata = [], ?bool $throttle = null): TemplateResponse {
		$response = new TemplateResponse(
			$appName,
			$templateName,
			$params,
			TemplateResponse::RENDER_AS_ERROR
		);
		$response->setStatus($statusCode);
		// if not specified, throttle if debug mode is off
		if (($throttle === null && !$this->isDebugModeEnabled()) || $throttle) {
			$response->throttle($throttleMetadata);
		}
		return $response;
	}
}
