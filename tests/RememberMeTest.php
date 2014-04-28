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
use SugiPHP\Auth\RememberMeInterface;
use SugiPHP\Auth\Exception as AuthException;

class RememberAuth extends Auth implements AuthInterface, RememberMeInterface
{
	public $data = array();

	public function __construct()
	{
		$_SESSION = array();
		parent::__construct(array());
	}

	public function getUserByUsername($username)
	{
		return array("id" => mt_rand(1, 1000), "username" => $username, "password" => $this->cryptSecret($username."123"), "state" => self::USER_STATE_ACTIVE);
	}

	public function getUserByEmail($email)
	{

	}

	public function getRememberMe($token)
	{
		return isset($this->data[$token]) ? $this->data[$token] : null;
	}

	public function addRememberMe($token, $time, $username)
	{
		$this->data[$token] = array("time" => $time, "username" => $username);
	}

	public function deleteRememberMe($token)
	{
		if (isset($this->data[$token])) {
			unset($this->data[$token]);
		}
	}

	// Cookie adapter
	public $cookie = array();
	public function setcookie($name, $value = null, $expire = 0, $path = null, $domain = null, $secure = false, $httponly = false)
	{
		if ($expire !== 0 and $expire < time()) {
			unset($this->cookie[$name]);
		} else {
			$this->cookie[$name] = $value;
		}
	}
	public function getcookie($name)
	{
		return isset($this->cookie[$name]) ? $this->cookie[$name] : null;
	}

	// exporting protected functions
	public function saveRememberMe($username)
	{
		return parent::saveRememberMe($username);
	}

	public function checkPersistentLogin()
	{
		return parent::checkPersistentLogin();
	}
}

class RememberMeTest extends PHPUnit_Framework_TestCase
{
	public function testSettingCookieAdapter()
	{
		$auth = new RememberAuth();
		$this->assertEmpty($auth->getcookie("test"));
		$auth->setcookie("test", "one");
		$this->assertSame("one", $auth->getcookie("test"));
		$auth->setcookie("test", "two", time() - 1000);
		$this->assertEmpty($auth->getcookie("test"));
	}

	public function testRememberNoLoggedInUserThrowsException()
	{
		$auth = new RememberAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::NO_USER);
		$auth->remember();
	}

	public function testSaveRememberMeAddsCookie()
	{
		$auth = new RememberAuth();
		$this->assertEmpty($auth->cookie);
		$auth->saveRememberMe("one");
		$this->assertNotEmpty($auth->cookie);
		$this->assertNotEmpty($auth->getcookie("AUTHREME"));
	}

	public function testSaveRememberMeSavesData()
	{
		$auth = new RememberAuth();
		$auth->saveRememberMe("one");
		$this->assertNotEmpty($auth->checkPersistentLogin());
	}

	public function testCheckPersistentLoginMeDestroysOldDataAndSavesNewData()
	{
		$auth = new RememberAuth();
		$auth->saveRememberMe("one");
		$old = $auth->data;
		$this->assertNotEmpty($auth->checkPersistentLogin());
		$new = $auth->data;
		$this->assertNotSame($old, $new);
	}

	public function testLoginAndRemeberMethod()
	{
		$auth = new RememberAuth();
		$auth->login("foo", "foo123");
		$auth->remember();
		$this->assertSame("foo", $auth->checkPersistentLogin());
	}

	public function testPersistentLogin()
	{
		$auth = new RememberAuth();
		$auth->login("foo", "foo123");
		$auth->remember();
		// mimics session expiration
		$_SESSION = array();
		$this->assertNull($auth->getUsername());
		$this->assertSame("foo", $auth->checkPersistentLogin());
		// the user is not logged in
		$this->assertNull($auth->getUsername());
		// user logs in
		$auth->checkLogin();
		$this->assertSame("foo", $auth->getUsername());
	}

	public function testLogoutDeletesPersistenLogin()
	{
		$auth = new RememberAuth();
		$auth->login("foo", "foo123");
		$auth->remember();
		$auth->logout();
		$this->assertNull($auth->checkPersistentLogin());
	}
}
