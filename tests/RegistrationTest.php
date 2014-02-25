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
use SugiPHP\Auth\RegistrationInterface;
use SugiPHP\Auth\Exception as AuthException;

class RegistrationAuth extends Auth implements AuthInterface, RegistrationInterface
{
	public $usernames = array();

	public function getUserByUsername($username)
	{
		return isset($this->usernames[$username]) ? $this->usernames[$username] : null;
	}

	public function getUserByEmail($email)
	{
		return isset($this->emails[$email]) ? $this->emails[$email] : null;
	}

	public function addUser($username, $email, $passwordHash, $state)
	{
		$id = count($this->usernames) + 1;
		$this->usernames[$username] = array("id" => $id, "username" => $username, "email" => $email, "password" => $passwordHash, "state" => $state);
		$this->emails[$email] = array("id" => $id, "username" => $username, "email" => $email, "password" => $passwordHash, "state" => $state);

		return $id;
	}

	public function updatePassword($username, $passwordHash)
	{
		$this->usernames[$username]["password"] = $passwordHash;
		$this->emails[$this->usernames[$username]["email"]]["password"] = $passwordHash;
	}

	public function updateState($username, $state)
	{
		$this->usernames[$username]["state"] = $state;
		$this->emails[$this->usernames[$username]["email"]]["state"] = $state;
	}
}

class RegistrationTest extends PHPUnit_Framework_TestCase
{
	public function testRegistration()
	{
		$_SESSION = array();
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->assertNotEmpty($user);
		$this->assertSame("foobar", $user["username"]);
		$this->assertSame("foobar@example.com", $user["email"]);
	}

	public function testRegistrationNoUsername()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_USERNAME);
		$user = $auth->register("", "foobar@example.com", "foobar123", "foobar123");
	}

	public function testRegistrationUsernameMismatch()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_USERNAME);
		$user = $auth->register("%^&", "foobar@example.com", "foobar123", "foobar123");
	}

	public function testRegistrationUsernameTooShort()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_USERNAME);
		$user = $auth->register("f", "foobar@example.com", "foobar123", "foobar123");
	}

	public function testRegistrationExistingUsername()
	{
		$auth = new RegistrationAuth();
		$auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::EXISTING_USERNAME);
		$auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
	}

	public function testRegistrationNoEmail()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_EMAIL);
		$user = $auth->register("foobar", "", "foobar123", "foobar123");
	}

	public function testRegistrationEmailMismatch()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_EMAIL);
		$user = $auth->register("foobar", "thisisnot#email", "foobar123", "foobar123");
	}

	public function testRegistrationExistingEmail()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::EXISTING_EMAIL);
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$user = $auth->register("foobar2", "foobar@example.com", "foobar123", "foobar123");
	}

	public function testRegistrationNoPasswordConfirmation()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_PASSWORD2);
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "");
	}

	public function testRegistrationPasswordTooSimple()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_PASSWORD);
		$user = $auth->register("foobar", "foobar@example.com", "foo", "foo");
	}

	public function testRegistrationPasswordConfirmationWrong()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::DIFFERENT_PASSWORD2);
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar1234");
	}

	public function testLoginBeforeActivation()
	{
		$auth = new RegistrationAuth();
		$auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_INACTIVE);
		$auth->login("foobar", "foobar123");
	}

	public function testActivationWithoutToken()
	{
		$auth = new RegistrationAuth();
		$auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_TOKEN);
		$auth->activate("foobar", "");
	}

	public function testActivationWrongToken()
	{
		$auth = new RegistrationAuth();
		$auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_TOKEN);
		$auth->activate("foobar", md5(rand()));
	}

	public function testActivationBlockedAccount()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->updateState("foobar", RegistrationAuth::USER_STATE_BLOCKED);
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_BLOCKED);
		$auth->activate("foobar", $user["token"]);
	}

	public function testActivationActiveAccount()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->updateState("foobar", RegistrationAuth::USER_STATE_ACTIVE);
		$auth->activate("foobar", $user["token"]); // OK to reactivate
	}

	public function testActivationWithPassword()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->activate("foobar", $user["token"], "foo1234", "foo1234");
		$this->assertNotEmpty($auth->login("foobar", "foo1234"));
		$auth->logout();
	}

	public function testActivationWithIllegalPassword()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::ILLEGAL_PASSWORD);
		$auth->activate("foobar", $user["token"], "f", "f");
	}

	public function testActivationWithMissingPasswordConfirmation()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::MISSING_PASSWORD2);
		$auth->activate("foobar", $user["token"], "foo1234", "");
	}

	public function testActivationWithWrongPasswordConfirmation()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::DIFFERENT_PASSWORD2);
		$auth->activate("foobar", $user["token"], "foo1234", "bar1234");
	}

	public function testActivationAndLogin()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->activate("foobar", $user["token"]);
		$active = $auth->getUserByUsername("foobar");
		$this->assertSame(RegistrationAuth::USER_STATE_ACTIVE, $active["state"]);
		$logged = $auth->login("foobar", "foobar123");
		$this->assertSame("foobar", $logged["username"]);
		$this->assertSame("foobar", $auth->getUsername());
		$auth->logout();
	}

	public function testBlockUnknownUserTrhowsException()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_NOT_FOUND);
		$auth->blockUser("foobar");
	}

	public function testBlockUser()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->blockUser("foobar");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_BLOCKED);
		$auth->activate("foobar", $user["token"]);
	}

	public function testBlockBlockedUser()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->blockUser("foobar");
		$auth->blockUser("foobar");
	}

	public function testUnblockUnknownUserTrhowsException()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_NOT_FOUND);
		$auth->unblockUser("foobar");
	}

	public function testUnblockUser()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->blockUser("foobar");
		$auth->unblockUser("foobar");
		$auth->activate("foobar", $user["token"]);
	}

	public function testUnblockActiveUser()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com", "foobar123", "foobar123");
		$auth->unblockUser("foobar");
	}

	public function testRegisterWithoutPassword()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com");
	}

	public function testRegistrationWithoutPasswordAndActivationWithoutPassword()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com");
		// TODO: Do we need to throw an exception here?
		$this->assertNotEmpty($auth->activate("foobar", $user["token"]));
	}

	public function testRegistrationWithoutPasswordAndActivationWithPassword()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com");
		$this->assertNotEmpty($auth->activate("foobar", $user["token"], "foobar123", "foobar123"));
		$this->assertNotEmpty($auth->login("foobar", "foobar123"));
		$auth->logout();
	}

	public function testGetToken()
	{
		$auth = new RegistrationAuth();
		$user = $auth->register("foobar", "foobar@example.com");
		$this->assertSame($user["token"], $auth->getToken("foobar"));
		$this->assertSame($user["token"], $auth->getToken("foobar@example.com"));
	}

	public function testGetActivationTokenUnknownUserThrowsException()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_NOT_FOUND);
		$auth->getToken("foobar");
	}

	public function testGetActivationTokenUnknownUserEmailThrowsException()
	{
		$auth = new RegistrationAuth();
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_NOT_FOUND);
		$auth->getToken("foobar@example.com");
	}

	public function testGetActivationTokenBlockedUserTrhowsException()
	{
		$auth = new RegistrationAuth();
		$auth->register("foobar", "foobar@example.com");
		$auth->blockUser("foobar");
		$this->setExpectedException("SugiPHP\Auth\Exception", "", AuthException::USER_BLOCKED);
		$auth->getToken("foobar");
	}

	// check set password
	// check password change (logged in user)
	// check password reset request
	// check password reset
}
