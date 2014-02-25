<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

class Exception extends \Exception
{
	const UNKNOWN_ERROR        = 0;
	const USER_ACTIVE          = 1;
	const USER_INACTIVE        = 2;
	const USER_BLOCKED         = 3;
	const MISSING_USERNAME     = 4; // missing username on logins and registration
	const MISSING_EMAIL        = 5; // missing email on registrations, password reset requests
	const MISSING_PASSWORD     = 6; // missing password on logins and registrations
	const MISSING_PASSWORD2    = 7; // missing password confirmation on registration and password changes, password resets and activations
	const MISSING_OLD_PASSWORD = 8; // missing old password when changing password
	const MISSING_TOKEN        = 9;
	const ILLEGAL_USERNAME     = 10;
	const ILLEGAL_PASSWORD     = 11;
	const ILLEGAL_EMAIL        = 12;
	const ILLEGAL_TOKEN        = 13;
	const LOGIN_FORBIDDEN      = 14;
	const LOGIN_FAILED         = 15;
	const USER_NOT_FOUND       = 16;
	const MULTIPLE_USERS       = 17;
	const NO_USER              = 18; // the user is not logged in
	const DIFFERENT_PASSWORD2  = 19;
	const EXISTING_USERNAME    = 20;
	const EXISTING_EMAIL       = 21;


	/**
	 * @var string
	 */
	protected $logMessage;

	/**
	 * Constructor.
	 *
	 * @param string $error This can be shown to end user.
	 * @param integer $code one of the defined errors.
	 * @param string $logMessage Log message is a message that is ready for logging. Should not be displayed to the end user.
	 */
	public function __construct($error, $code = 0, $logMessage = "")
	{
		parent::__construct($error, $code);

		$this->logMessage = $logMessage;
	}

	/**
	 * Returns a log message if available, otherwise $error
	 *
	 * @return string
	 */
	public function getLogMessage()
	{
		return $this->logMessage ? $this->logMessage : $this->getMessage();
	}
};
