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
	const UNKNOWN_ERROR       = 0;
	const MISSING_USERNAME    = 1;
	const MISSING_PASSWORD    = 2;
	const MISSING_EMAIL       = 3;
	const ILLEGAL_USERNAME    = 4;
	const ILLEGAL_PASSWORD    = 5;
	const ILLEGAL_EMAIL       = 6;
	const LOGIN_FORBIDDEN     = 8;
	const LOGIN_FAILED        = 9;
	const USER_NOT_FOUND      = 10;
	const MULTIPLE_USERS      = 11;
	const USER_NOT_ACTIVE     = 12;
	const USER_NOT_BLOCKED    = 13;
	const USER_ACTIVE         = 14;
	const USER_INACTIVE       = 15;
	const USER_BLOCKED        = 16;
	const MISSING_TOKEN       = 17;
	const WRONG_TOKEN         = 18;
	const NOT_LOGGED_IN       = 19;
	const MISSING_PASSWORD2   = 20;
	const DIFFERENT_PASSWORD2 = 21;


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
