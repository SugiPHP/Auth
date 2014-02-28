<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @category   tests
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

use SugiPHP\Auth\Auth;
use SugiPHP\Auth\AuthInterface;
use SugiPHP\Auth\Exception as AuthException;


class NotAuth extends Auth
{

}

class LoginOnlyAuth extends Auth implements AuthInterface
{
	public function getUserByUsername($username)
	{
		if ($username == "null") {
			return null;
		}
		if ($username == "inact") {
			$state = Auth::USER_STATE_INACTIVE;
		} elseif ($username == "blckd") {
			$state = Auth::USER_STATE_BLOCKED;
		} else {
			$state = Auth::USER_STATE_ACTIVE;
		}

		return array("username" => $username, "password" => $this->cryptSecret($username."123"), "state" => $state);
	}

	public function getUserByEmail($email)
	{
		$username = explode("@", $email)[0];

		if ($username == "null") {
			return null;
		}
		if ($username == "inact") {
			$state = Auth::USER_STATE_INACTIVE;
		} elseif ($username == "blckd") {
			$state = Auth::USER_STATE_BLOCKED;
		} else {
			$state = Auth::USER_STATE_ACTIVE;
		}

		return array("username" => $username, "password" => $this->cryptSecret($username."123"), "state" => $state);
	}
}

class AuthTest extends PHPUnit_Framework_TestCase
{
	public function testAuthCreation()
	{
		$this->setExpectedException("SugiPHP\Auth\InternalException");
		$auth = new Auth();
	}

	public function testAuthImplementsAuthInterface()
	{
		$this->setExpectedException("SugiPHP\Auth\InternalException");
		$auth = new NotAuth();
	}

	public function testLoginOnlyAuth()
	{
		$_SESSION = array();
		$auth = new LoginOnlyAuth();
	}

	public function testCheckSecretAndCryptSecret()
	{
		$auth = new LoginOnlyAuth();
		$hash = $auth->cryptSecret("");
		$this->assertTrue($auth->checkSecret($hash, ""));
		$this->assertFalse($auth->checkSecret($hash, "foo"));
		$hash = $auth->cryptSecret("foo");
		$this->assertTrue($auth->checkSecret($hash, "foo"));
		$this->assertFalse($auth->checkSecret($hash, "bar"));
		$this->assertFalse($auth->checkSecret($hash, ""));
		$random = md5(time());
		$hash = $auth->cryptSecret($random);
		$this->assertTrue($auth->checkSecret($hash, $random));
	}

	public function testLoginNoUsernameThrowsException()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_USERNAME);
		$auth->login("", "");
	}

	public function testLoginNoPasswordThrowsException()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_PASSWORD);
		$auth->login("foo", "");
	}

	public function testLoginWrongUsername()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FAILED);
		$auth->login("null", "null123");
	}

	public function testLoginWrongPass()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FAILED);
		$auth->login("foo", "wrongpass");
	}

	public function testLoginSuccess()
	{
		$auth = new LoginOnlyAuth();
		$this->assertNotEmpty($user = $auth->login("foo", "foo123"));
		$this->assertNotEmpty($auth->getUser());
		$this->assertSame("foo", $auth->getUsername());
		$this->assertFalse("foo2" == $auth->getUsername());
	}

	public function testNotImplementedRememberMeInterfaceThrowsExceptionOnLogin()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\InternalException");
		$auth->login("foo", "foo123", true);
	}

	public function testNotImplementedRememberMeInterfaceThrowsExceptionOnRememberMethod()
	{
		$auth = new LoginOnlyAuth();
		$auth->login("foo", "foo123");
		$this->setExpectedException("SugiPHP\Auth\InternalException");
		$auth->remember();
	}

	public function testEmailLoginNoPasswordThrowsException()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_PASSWORD);
		$auth->login("foo@example.com", "");
	}

	public function testEmailLoginEmailMismatch()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_EMAIL);
		$auth->login("null@", "null123");
	}

	public function testEmailLoginWrongEmail()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FAILED);
		$auth->login("null@example.com", "null123");
	}

	public function testEmailLoginWrongPass()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FAILED);
		$auth->login("bar@example.com", "wrongpass");
	}

	public function testEmailLoginSuccess()
	{
		$auth = new LoginOnlyAuth();
		$this->assertNotEmpty($user = $auth->login("bar@example.com", "bar123"));
		$this->assertSame("bar", $auth->getUsername());
		$this->assertFalse("bar2" == $auth->getUsername());
		$this->assertNotEmpty($auth->getUser());
	}

	public function testLogotSuccess()
	{
		$auth = new LoginOnlyAuth();
		$this->assertNotEmpty($user = $auth->login("bar@example.com", "bar123"));
		$auth->logout();
		$this->assertEmpty($auth->getUser());
		$this->assertEmpty($auth->getUsername());
	}

	public function testLoginFailNotActiveAccount()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_INACTIVE);
		$auth->login("inact", "wrongpass");
	}

	public function testLoginNotActiveAccount()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_INACTIVE);
		$auth->login("inact", "inact123");
	}

	public function testLoginFailBlockedAccount()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_BLOCKED);
		$auth->login("blckd", "wrongpass");
	}

	public function testLoginBlockedAccount()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_BLOCKED);
		$auth->login("blckd", "blckd123");
	}
}
