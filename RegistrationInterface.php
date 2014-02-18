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
	 * Invoked by Auth::addUser()
	 *
	 * @param  string $username
	 * @return mixed Returns FALSE if user is not found or array with "id", "username", "password", "state", "email", etc.
	 */
	public function getUserByEmail($email);

	/**
	 * Invoked by Auth::createUser()
	 *
	 * @param  string $username
	 * @param  string $email
	 * @param  string $passwordHash
	 * @param  integer $state
	 * @return integer Newly created user_id of FALSE on error
	 */
	public function addUser($username, $email, $passwordHash, $state);

	/**
	 * Sets user password.
	 *
	 * @param integer $user_id
	 * @param string $passwordHash Crypted password
	 */
	public function updatePassword($user_id, $passwordHash);


	/**
	 * Changes user state.
	 *
	 * @param integer $user_id
	 * @param integer $state
	 */
	public function updateState($user_id, $state);
}
