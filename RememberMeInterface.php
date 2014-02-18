<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface RememberMeInterface
{
	/**
	 * Checks the user has a valid "Remember Me" token.
	 *
	 * @param  string $tokenHash
	 * @return array ["time" => (integer) Login time, "user" => (mixed) User ID]
	 */
	public function getRememberMe($tokenHash);

	/**
	 * Saves a remember me token.
	 *
	 * @param  string $tokenHash
	 * @param  integer $tokenTime
	 * @param  mixed $user
	 */
	public function addRememberMe($tokenHash, $tokenTime, $user);

	/**
	 * Deletes a token for persistent login to be sure that it has been disabled for login.
	 * This method is invoked when a token is used for logging in and for logout.
	 *
	 * @param  string $tokenHash
	 */
	public function deleteRememberMe($tokenHash);

	/**
	 * When a user wants to delete all saved remember me tokens from all computers.
	 * TODO: make a function in Auth that will execute it with logged in user.
	 *
	 * @param  mixed $userId
	 */
	public function deleteRememberMeForUser($user);
}
