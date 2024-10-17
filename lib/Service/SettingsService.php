<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
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
use OCP\IConfig;

class SettingsService {

	public function __construct(
		private IConfig $config,
	) {
	}

	public function getAllowMultipleUserBackEnds(): bool {
		return $this->config->getAppValue(Application::APP_ID, 'allow_multiple_user_backends', '1') === '1';
	}

	public function setAllowMultipleUserBackEnds(bool $value): void {
		$this->config->setAppValue(Application::APP_ID, 'allow_multiple_user_backends', $value ? '1' : '0');
	}
}
