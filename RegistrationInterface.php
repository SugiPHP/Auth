<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface RegistrationInterface
{
	/**
	 * Invoked by Auth::createUser()
	 *
	 * @param  string  $username
	 * @param  string  $email
	 * @param  string  $passwordHash
	 * @param  integer $state
	 * @return FALSE on error. Any other result will be returned in "data" key
	 */
	public function addUser($username, $email, $passwordHash, $state);

	/**
	 * Sets user password.
	 *
	 * @param string $username
	 * @param string $passwordHash Crypted password
	 */
	public function updatePassword($username, $passwordHash);


	/**
	 * Changes user state.
	 *
	 * @param string  $username
	 * @param integer $state
	 */
	public function updateState($username, $state);
}
