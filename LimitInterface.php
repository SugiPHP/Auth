<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface LimitInterface
{
	/**
	 * Returns the number of failed login attempts.
	 * Invoked by Auth::checkCredentials()
	 *
	 * @param  integer $user_id
	 * @return integer
	 */
	public function getLoginAttempts($user_id);

	/**
	 * Increases number of failed login attempts.
	 * Invoked by Auth::checkCredentials()
	 *
	 * @param integer $user_id
	 */
	public function increaseLoginAttempts($user_id);

	/**
	 * Resets number (sets to 0) of failed login attempts.
	 * Invoked by Auth::checkCredentials()
	 *
	 * @param integer $user_id
	 */
	public function resetLoginAttempts($user_id);
}
