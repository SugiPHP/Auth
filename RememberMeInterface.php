<?php
/**
 * @package SugiPHP.Auth
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface RememberMeInterface
{
    /**
     * Checks the user has a valid "Remember Me" token.
     *
     * @param  string $token The hashed token
     * @return array|NULL Returns NULL if there is no record matching $token or array ["time" => (integer) Login time, "username" => (string) Username]
     */
    public function getRememberMe($token);

    /**
     * Saves a remember me token.
     *
     * @param string $token Hashed token
     * @param integer $time
     * @param string $user
     */
    public function addRememberMe($token, $time, $username);

    /**
     * Deletes a token for persistent login to be sure that it has been disabled for login.
     * This method is invoked when a token is used for logging in and for logout.
     *
     * @param string $token Hashed token
     */
    public function deleteRememberMe($token);
}
