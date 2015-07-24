<?php
/**
 * @package SugiPHP.Auth
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

interface LimitInterface
{
    /**
     * Returns the number of failed login attempts.
     * Invoked by Auth::checkCredentials()
     *
     * @param  string $username
     * @return integer
     */
    public function getLoginAttempts($username);

    /**
     * Increases number of failed login attempts.
     * Invoked by Auth::checkCredentials()
     *
     * @param string $username
     */
    public function increaseLoginAttempts($username);

    /**
     * Resets number (sets to 0) of failed login attempts.
     * Invoked by Auth::checkCredentials()
     *
     * @param string $username
     */
    public function resetLoginAttempts($username);
}
