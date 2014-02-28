<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface AuthInterface
{
	/**
	 * Invoked by Auth::checkCredentials()
	 *
	 * @param  string $username
	 * @return mixed Returns FALSE if user is not found or array with "username", "password", "state", "email" and optionally "login_attempts"
	 */
	public function getUserByUsername($username);

	/**
	 * Invoked by Auth::checkCredentials() and Auth::addUser()
	 *
	 * @param  string $username
	 * @return mixed Returns FALSE if user is not found or array with "username", "password", "state", "email" and optionally "login_attempts"
	 */
	public function getUserByEmail($email);
}
