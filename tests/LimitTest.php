<?php
/**
 * @package SugiPHP.Auth
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

use SugiPHP\Auth\Auth;
use SugiPHP\Auth\AuthInterface;
use SugiPHP\Auth\LimitInterface;
use SugiPHP\Auth\Exception as AuthException;

class LimitAuth extends Auth implements AuthInterface, LimitInterface
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

    // per user login attempts
    protected $loginAttemps = array();

    public function getLoginAttempts($username)
    {
        return isset($this->loginAttemps[$username]) ? $this->loginAttemps[$username] : 0;
    }

    public function increaseLoginAttempts($username)
    {
        $this->loginAttemps[$username] = isset($this->loginAttemps[$username]) ? $this->loginAttemps[$username] + 1 : 1;
    }

    public function resetLoginAttempts($username)
    {
        $this->loginAttemps[$username] = 0;
    }
}

class LimitTest extends PHPUnit_Framework_TestCase
{
    public function testGetLoginAttempts()
    {
        $auth = new LimitAuth();
        $this->assertSame(0, $auth->getLoginAttempts("foo"));
    }

    public function testIncreaseLoginAttempts()
    {
        $auth = new LimitAuth();
        $this->assertSame(0, $auth->getLoginAttempts("foo"));
        $auth->increaseLoginAttempts("foo");
        $this->assertSame(1, $auth->getLoginAttempts("foo"));
        $auth->increaseLoginAttempts("foo");
        $this->assertSame(2, $auth->getLoginAttempts("foo"));
    }

    public function testResetLoginAttempts()
    {
        $auth = new LimitAuth();
        $auth->increaseLoginAttempts("foo");
        $auth->increaseLoginAttempts("foo");
        $this->assertSame(2, $auth->getLoginAttempts("foo"));
        $auth->resetLoginAttempts("foo");
        $this->assertSame(0, $auth->getLoginAttempts("foo"));
    }

    public function testLoginSuccess()
    {
        $auth = new LimitAuth();
        $this->assertNotEmpty($user = $auth->login("foo", "foo123"));
        $this->assertSame("foo", $auth->getUsername());
    }

    public function testLoginFailsIncreasesLoginAttempts()
    {
        $auth = new LimitAuth();
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        $this->assertSame(1, $auth->getLoginAttempts("foo"));
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        $this->assertSame(2, $auth->getLoginAttempts("foo"));
    }

    public function testLoginSuccessResetsPasswordLoginAttempts()
    {
        $auth = new LimitAuth();
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        $this->assertNotEmpty($user = $auth->login("foo", "foo123"));
        $this->assertSame(0, $auth->getLoginAttempts("foo"));
    }

    public function testLoginThrowsExceptionOnTooMuchLoginAttempts()
    {
        $auth = new LimitAuth(array("block_logins_after" => 2));
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        $this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FORBIDDEN);
        $auth->login("foo", "wrongpass");
    }

    public function testLoginFailsWhenLoginAttemptsAreTooMuch()
    {
        $auth = new LimitAuth(array("block_logins_after" => 2));
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        try {
            $auth->login("foo", "wrongpass");
        } catch(SugiPHP\Auth\Exception $e) {}
        $this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::LOGIN_FORBIDDEN);
        $auth->login("foo", "foo123");
    }
}
