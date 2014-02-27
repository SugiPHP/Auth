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

	public function checkRememberMe()
	{
		return parent::checkRememberMe();
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
		$this->assertNotEmpty($auth->checkRememberMe());
	}

	public function testChechRememberMeDestroysOldDataAndSavesNewData()
	{
		$auth = new RememberAuth();
		$auth->saveRememberMe("one");
		$old = $auth->data;
		$this->assertNotEmpty($auth->checkRememberMe());
		$new = $auth->data;
		$this->assertNotSame($old, $new);
	}
}
