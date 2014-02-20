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

		return array("id" => mt_rand(1, 1000), "username" => $username, "password" => $this->cryptSecret($username."123"), "state" => 1);
	}

	public function getUserByEmail($email)
	{
		$username = explode("@", $email)[0];

		if ($username == "null") {
			return null;
		}

		return array("id" => mt_rand(1, 1000), "username" => $username, "password" => $this->cryptSecret($username."123"), "state" => 1);
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
		$auth->login("foo", "foo");
	}

	public function testLoginSuccess()
	{
		$auth = new LoginOnlyAuth();
		$this->assertNotEmpty($user = $auth->login("foo", "foo123"));
	}

	public function testEmailLoginNoPasswordThrowsException()
	{
		$auth = new LoginOnlyAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_PASSWORD);
		$auth->login("foo@example.com", "");
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
		$auth->login("foo@example.com", "foo");
	}

	public function testEmailLoginSuccess()
	{
		$auth = new LoginOnlyAuth();
		$this->assertNotEmpty($user = $auth->login("foo@example.com", "foo123"));
	}
}