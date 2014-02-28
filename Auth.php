<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

class Auth
{
	/*
	 * User States
	 */
	const USER_STATE_ACTIVE    = 1;
	const USER_STATE_INACTIVE  = 2;
	const USER_STATE_BLOCKED   = 3;

	/**
	 * Storage for configuration settings
	 * @var array
	 */
	protected $config = array();

	/**
	 * Constructor.
	 *
	 * @param array $config Configuration options
	 */
	public function __construct(array $config = array())
	{
		if (!$this instanceof AuthInterface) {
			throw new InternalException("To use Auth you must implement AuthInterface");
		}

		// Default configuration options
		$this->config = array(
			// check for login on construct
			"auto_check_login"         => true,
			// Maximum number of login attempts before blocking (only for log in) the user. FALSE means no blocking.
			"block_logins_after"       => 24,
			// If remember me option was checked for how long remember me cookie and DB info should stay in seconds. Defaults to 90 days.
			"remember_me_time"         => 7776000,
			// cookie name for persistent logins (remember me)
			"remember_me_cookie_name"  => "AUTHREME",
		);

		// Override default options
		foreach ($this->config as $name => $def) {
			if (isset($config[$name])) {
				$this->config[$name] = $config[$name];
			}
		}

		if ($this->config["auto_check_login"]) {
			$this->checkLogin();
		}
	}

	public function checkLogin()
	{
		if (!$username = $this->getUsername()) {
			// not logged in (session expired). will check for permanent login (remember me)
			if ($this->config["remember_me_time"] and $this instanceof RememberMeInterface) {
				$username = $this->checkPersistentLogin();
			}
		}

		if ($username) {
			$user = $this->getUserByUsername($username);
			if (!$user) {
				$this->flushUserData();
				throw new Exception("User is not logged in", Exception::NO_USER);
			}

			if ($user["state"] == self::USER_STATE_BLOCKED) {
				$this->flushUserData();
				throw new Exception("User account is blocked", Exception::USER_BLOCKED, "Logged in user {$this->getUsername()} is blocked");
			}

			if ($user["state"] != self::USER_STATE_ACTIVE) {
				$this->flushUserData();
				throw new Exception("Unknown user state", Exception::USER_INACTIVE, "Logged in user $username is not active ({$user["state"]})");
			}

			// saves a data in the session
			$this->setUserData($user);
		}
	}

	/**
	 * Logged in User ID
	 *
	 * @return mixed User's ID or NULL if not logged in
	 */
	public function getUser()
	{
		return $this->getUserData();
	}

	/**
	 * Logged in user's username.
	 *
	 * @return mixed User's username or NULL if not logged in
	 */
	public function getUsername()
	{
		return $this->getUserData("username");
	}

	/**
	 * Check the user can login with given username or email and password.
	 *
	 * @param  string  $username/email
	 * @param  string  $password
	 * @param  boolean $remember If it's set and RememberMeInterface is implemented then it adds a record in the DB and sets a cookie for a user to be remembered.
	 *
	 * @throws Exception If username/email or password are illegal
	 * @throws Exception If user not found
	 * @throws Exception If the user has been blocked (for login) for too many login attempts.
	 */
	public function login($username, $password, $remember = false)
	{
		$this->flushUserData();

		// Login with
		if ($emailLogin = (strpos($username, "@") > 0)) {
			// checks email and throws Exception on error
			$this->checkEmail($username);
		} else {
			// checks username and throws Exception on error
			$this->checkUsername($username);
		}

		// checks password is set
		if ( ! $password) {
			throw new Exception("Required password is missing", Exception::MISSING_PASSWORD);
		}

		// @see AuthInterface
		$user = $emailLogin ? $this->getUserByEmail($username) : $this->getUserByUsername($username);

		// no such user
		if ( ! $user) {
			throw new Exception("Username/password mismatch", Exception::LOGIN_FAILED, "User $username not found");
		}

		$username = $user["username"];

		if ($user["state"] == self::USER_STATE_INACTIVE) {
			throw new Exception("Before login you have to confirm your email address", Exception::USER_INACTIVE, "Login attempt for user $username with not confirmed email address");
			// here we can show "resend activation" link
		}

		if ($this instanceof LimitInterface) {
			// how many times user has failed to login.
			if (!isset($user["login_attempts"])) {
				$user["login_attempts"] = $this->getLoginAttempts($username);
			}

			// check for failed login attempts
			if ($this->config["block_logins_after"] and ($user["login_attempts"] > $this->config["block_logins_after"])) {
				// block user
				throw new Exception("Access denied. Too many login attempts",
						Exception::LOGIN_FORBIDDEN,
						"Too many ({$user["login_attempts"]}) login requests (max {$this->config["block_logins_after"]}) for user $username. The user is blocked!");
			}
		}

		if ($user["state"] == self::USER_STATE_BLOCKED) {
			throw new Exception("User account is blocked", Exception::USER_BLOCKED, "Login attempt for blocked user $username");
		}

		if ($user["state"] != self::USER_STATE_ACTIVE) {
			throw new Exception("Unknown user state", Exception::USER_INACTIVE, "Login attempt for user $username with unknown user state ({$user["state"]})");
		}

		// check password
		if ( ! $this->checkSecret($user["password"], $password)) {
			if ($this instanceof LimitInterface) {
				$this->increaseLoginAttempts($username);
			}
			throw new Exception("Username/password mismatch", Exception::LOGIN_FAILED, "User $username supplied wrong password.");
		}

		// reset failed login attempts
		if (($this instanceof LimitInterface) and ($user["login_attempts"] > 0)) {
			$this->resetLoginAttempts($username);
		}

		$this->setUserData($user);

		if ($remember) {
			$this->remember();
		}

		return $user;
	}

	/**
	 * When the user logs out.
	 */
	public function logout()
	{
		$this->flushUserData();
		// checks for persistent logins and if found deletes it.
		if ($token = $this->getRememberMeCookie()) {
			$this->setRememberMeCookie();
			if ($this instanceof RememberMeInterface) {
				$this->deleteRememberMe(hash("sha256", $token, false));
			}
		}
	}

	/**
	 * Saves logged in user data. Persistent login (aka Remember Me)
	 */
	public function remember()
	{
		if (!$username = $this->getUserData("username")) {
			throw new Exception("Cannot remember not logged in user", Exception::NO_USER);
		}

		$this->saveRememberMe($username);
	}

	/**
	 * User registration.
	 * Can be done by the user providing password, or can be done from administrator without
	 * providing password. On activation process the user can set his/her password.
	 *
	 * @param  string $username
	 * @param  string $email
	 * @param  string $password (optional)
	 * @param  string $password2 Password confirmation (optional)
	 * @return array  User info
	 * @throws Exception On any error
	 */
	public function register($username, $email, $password = null, $password2 = null)
	{
		$email = mb_strtolower($email, "UTF-8");
		// checks username and throws Exception on error
		$this->checkUsername($username);
		// checks email addresses and throws Exception on error
		$this->checkEmail($email);

		if (!is_null($password)) {
			// Check for password strength
			$this->checkPassStrength($password);
			// Check passwords match
			$this->checkPasswordConfirmation($password, $password2);
			// crypt password
			$password = $this->cryptSecret($password);
		} else {
			// create a unique password, which cannot be used for login, but it is used to form unique token for account activation
			$password = $this->cryptSecret(mt_rand().uniqid().time());
		}

		// check username is unique
		if ($this->getUserByUsername($username)) {
			throw new Exception("The username provided already exists", Exception::EXISTING_USERNAME, "Username $username exists");
		}
		// check email is unique
		if ($this->getUserByEmail($email)) {
			throw new Exception("There is a user registered with this email", Exception::EXISTING_EMAIL, "Email $email exists");
		}

		// insert in the DB and get new user's ID or some other data that will be returned
		if (!$data = $this->addUser($username, $email, $password, self::USER_STATE_INACTIVE)) {
			throw new Exception("Error creating user", Exception::UNKNOWN_ERROR, "Error while inserting user in the DB with username $username and email $email");
		}

		// creating unique token
		$token = sha1($username . $password . $email);

		// return token for account activation via e-mail
		return array("username" => $username, "email" => $email, "state" => self::USER_STATE_INACTIVE, "token" => $token, "data" => $data);
	}

	/**
	 * Activates account and sets a new password (if the user does not have a password)
	 *
	 * @param  string $username
	 * @param  string $token
	 * @param  string|NULL $password If the user did not provide password on registration this should be set here
	 * @param  string|NULL $password2 Checked only $password is not null
	 * @return array User info
	 */
	public function activate($username, $token, $password = null, $password2 = null)
	{
		// check activation token
		$user = $this->checkToken($username, $token);

		if (!is_null($password)) {
			// Check for password strength
			$this->checkPassStrength($password);
			// Check passwords match
			$this->checkPasswordConfirmation($password, $password2);
		}

		// Activate user. The check is because this method handles reset password requests also
		if ($user["state"] == self::USER_STATE_INACTIVE) {
			$this->updateState($username, self::USER_STATE_ACTIVE);
		}

		if (!is_null($password)) {
			// setting up a new password
			$this->setPassword($username, $password);
		}

		// NOTE:
		//
		// Here we can automatically sign in the user ONLY if the password is set here.
		// If the password was supplied in a registration form the token will not change,
		// and the user could sign in again and again only with the link provided in the mail
		//

		return array("username" => $user["username"], "email" => $user["email"], "state" => $user["state"]);
	}

	/**
	 * Sets a new user password.
	 *
	 * @param  string $username
	 * @param  string $password
	 * @throws Exception If password is too weak
	 */
	public function setPassword($username, $password)
	{
		// @see AuthInterface::updatePassword();
		$this->updatePassword($username, $this->cryptSecret($password));
	}

	/**
	 * Changes user's password.
	 *
	 * @param  string $old Current user's password
	 * @param  string $password New user's password
	 * @param  string $password2 New user's password confirmation
	 * @throws Exception On any error
	 */
	public function changePassword($old, $password, $password2)
	{
		if ( ! $username = $this->getUsername()) {
			throw new Exception("User is not logged in", Exception::NO_USER);
		}

		if ( ! $old = trim($old)) {
			throw new Exception("Enter your old password", Exception::MISSING_OLD_PASSWORD);
		}

		// Check for password strength
		$this->checkPassStrength($password);
		// Check passwords match
		$this->checkPasswordConfirmation($password, $password2);

		// check old password
		$user = $this->getUserByUsername($username);
		if ( ! $this->checkSecret($user["password"], $old)) {
			throw new Exception("Your old password do not match", Exception::LOGIN_FAILED, "User $username supplied wrong password.");
		}

		// setting up a new password
		$this->setPassword($username, $password);
	}

	/**
	 * Returns activation / forgot password token for a user
	 * This is used when a user wants to resend activation email.
	 *
	 * @param  string $usernameOrEmail Username or email
	 * @throws Exception On any error
	 */
	public function getToken($usernameOrEmail)
	{
		if (strpos($usernameOrEmail, "@") > 0) {
			$email = $usernameOrEmail;
			// checks email and throws Exception on error
			$this->checkEmail($email);
			// finding user
			if (!$user = $this->getUserByEmail($email)) {
				throw new Exception("User email not found", Exception::USER_NOT_FOUND, "User with email $email not found");
			}
		} else {
			$username = $usernameOrEmail;
			// checks username and throws Exception on error
			$this->checkUsername($username);
			// finding user
			if (!$user = $this->getUserByUsername($username)) {
				throw new Exception("Username not found", Exception::USER_NOT_FOUND, "User with username $username not found");
			}
		}

		// check user is blocked
		if ($user["state"] == self::USER_STATE_BLOCKED) {
			throw new Exception("User account is blocked", Exception::USER_BLOCKED);
		}

		return sha1($user["username"] . $user["password"] . $user["email"]);
	}

	/**
	 * Blocks user account. No login, activation, or changing password can be done
	 *
	 * @param  string $username
	 */
	public function blockUser($username)
	{
		// checks username and throws Exception on error
		$this->checkUsername($username);

		// finding user
		if (!$user = $this->getUserByUsername($username)) {
			throw new Exception("Username not found", Exception::USER_NOT_FOUND, "User with username $username not found");
		}

		// Activate user
		$this->updateState($user["username"], self::USER_STATE_BLOCKED);
	}

	/**
	 * Unblocks user account.
	 *
	 * @param  string $username
	 */
	public function unblockUser($username)
	{
		// checks username and throws Exception on error
		$this->checkUsername($username);

		// finding user
		if (!$user = $this->getUserByUsername($username)) {
			throw new Exception("Username not found", Exception::USER_NOT_FOUND, "User with username $username not found");
		}

		// Activate user
		$this->updateState($user["username"], self::USER_STATE_ACTIVE);
	}

	/**
	 * Forgot password request.
	 *
	 * @param  string $email
	 * @return array User info
	 * @throws AuthException On any error
	 */
	public function forgotPassword($email)
	{
		$this->checkEmail($email);

		$user = $this->getUserByEmail($email);

		if (!$user) {
			throw new Exception("User with email provided not found", Exception::USER_NOT_FOUND);
		}

		if ($user["state"] == self::USER_STATE_BLOCKED) {
			throw new Exception("User account is blocked", Exception::USER_BLOCKED);
		}

		// make some secret hash for password reset
		$token = sha1($user["username"] . $user["password"] . $user["email"]);

		return array("username" => $user["username"], "email" => $user["email"], "state" => $user["state"], "token" => $token);
	}

	/**
	 * Reset password request.
	 *
	 * @param  string $username
	 * @param  string $token
	 * @param  string $password
	 * @param  string $password2
	 * @return array  User info
	 */
	public function resetPassword($username, $token, $password, $password2)
	{
		// cannot send null in activate() method, so we'll check it here
		if (is_null($password)) {
			throw new Exception("Required password is missing", Exception::MISSING_PASSWORD);
		}

		return $this->activate($username, $token, $password, $password2);
	}

	/**
	 * Compares a secret against a hash.
	 *
	 * @param string $hash Secret hash made with cryptSecret() method
	 * @param string $secret Secret
	 * @return boolean
	 */
	public function checkSecret($hash, $secret)
	{
		return ($hash === crypt($secret, substr($hash, 0, 29)));
	}

	/**
	 * Generates a hash.
	 *
	 * @param string $secret
	 * @return string
	 */
	public function cryptSecret($secret)
	{
		return crypt($secret, '$2a$10$' . substr(sha1(mt_rand()), 0, 22));
	}

	protected function checkToken($username, $token)
	{
		// checks username and throws Exception on error
		$this->checkUsername($username);

		// check token
		if (!$token = trim($token)) {
			throw new Exception("Required token parameter is missing", Exception::MISSING_TOKEN);
		}

		// finding user
		if (!$user = $this->getUserByUsername($username)) {
			throw new Exception("Username not found", Exception::USER_NOT_FOUND, "User with username $username not found");
		}

		// check user is blocked
		if ($user["state"] == self::USER_STATE_BLOCKED) {
			throw new Exception("User account is blocked", Exception::USER_BLOCKED);
		}

		// check token
		if ($token != sha1($user["username"] . $user["password"] . $user["email"])) {
			throw new  Exception("Invalid activation token", Exception::ILLEGAL_TOKEN);
		}

		return $user;
	}

	/**
	 * Checks for persistent cookie if it was set with "Remember Me" option.
	 *
	 * @return mixed The username or NULL when there is no data for persistent login.
	 */
	protected function checkPersistentLogin()
	{
		if ($token = $this->getRememberMeCookie()) {
			$tokenHash = hash("sha256", $token, false);
			if ($data = $this->getRememberMe($tokenHash)) {
				// Always delete used token.
				// Persistent tokens can be used only once!
				$this->deleteRememberMe($tokenHash);

				// check the token is expired
				if ($data["time"] + $this->config["remember_me_time"] > time()) {
					$this->saveRememberMe($data["username"]);

					return $data["username"];
				} else {
					$this->setRememberMeCookie();
				}
			}
		}
	}

	protected function saveRememberMe($username)
	{
		if (!$this instanceof RememberMeInterface) {
			throw new InternalException("To use remember me functionality you must implement RememberMeInterface");
		}
		if ($this->config["remember_me_time"] <= 0) {
			throw new InternalException("Remember Me time is not set or illegal");
		}
		$token = $this->genToken();
		$tokenHash = hash("sha256", $token, false);
		$this->addRememberMe($tokenHash, time(), $username);
		$this->setRememberMeCookie($token);
	}

	protected function setRememberMeCookie($token = false)
	{
		if ($token) {
			$exp = time() + $this->config["remember_me_time"];
		} else {
			// removes the cookie
			$token = "";
			$exp = time() - 153792000;
		}

		if (isset($_SERVER["HTTP_HOST"])) {
			$this->setcookie($this->config["remember_me_cookie_name"], $token, $exp, "/", $_SERVER["HTTP_HOST"], !empty($_SERVER["HTTPS"]), true);
		} else {
			$this->setcookie($this->config["remember_me_cookie_name"], $token, $exp);
		}
	}

	protected function getRememberMeCookie()
	{
		return $this->getcookie($this->config["remember_me_cookie_name"]);
	}

	/**
	 * Sets user data in the session. Override this method to use other storage.
	 *
	 * @param string $key
	 * @param mixed $value Value to be stored.
	 */
	protected function setUserData($key, $value = null)
	{
		if (is_array($key)) {
			$_SESSION["userdata"] = $key;
		} else {
			$_SESSION["userdata"][$key] = $value;
		}
	}

	/**
	 * Removes any stored user data. Override this method to use other storage.
	 */
	protected function flushUserData()
	{
		unset($_SESSION["userdata"]);
	}

	/**
	 * Gets previously stored user data in the session. Override this method to use other storage.
	 *
	 * @param  string $key
	 * @param  mixed  $default
	 * @return mixed
	 */
	protected function getUserData($key = null, $default = null)
	{
		if (is_null($key)) {
			return (isset($_SESSION["userdata"])) ? $_SESSION["userdata"] : $default;
		}

		return (isset($_SESSION["userdata"][$key])) ? $_SESSION["userdata"][$key] : $default;
	}

	/**
	 * Checks username is valid.
	 *
	 * @throws Exception If username is missing, has less than 3 chars, more than 32 or contains chars that are not allowed
	 * @param  string $username
	 */
	protected function checkUsername($username)
	{
		if ( ! $username) {
			throw new Exception("Required username is missing", Exception::MISSING_USERNAME);
		}
		if (mb_strlen($username, "UTF-8") < 3) {
			throw new Exception("Username too short", Exception::ILLEGAL_USERNAME, "Username mismatch - less than 3 chars");
		}
		if (mb_strlen($username, "UTF-8") > 32) {
			throw new Exception("Username too long", Exception::ILLEGAL_USERNAME, "Username mismatch - more than 32 chars");
		}
		if ( ! preg_match("#^[a-z]([a-z0-9-_\.])+$#i", $username)) {
			throw new Exception("Illegal username", Exception::ILLEGAL_USERNAME, "Username contains chars that are not allowed");
		}
	}

	/**
	 * Checks email is valid.
	 *
	 * @throws Exception If email is missing, is longer than 255 chars, and is not valid
	 * @param  string $email
	 */
	protected function checkEmail($email)
	{
		if ( ! $email) {
			throw new Exception("Required email is missing", Exception::MISSING_EMAIL);
		}
		// TODO: this should be in a user's model
		// if (mb_strlen($email, "UTF-8") > 255) {
		// 	throw new Exception("Email address too long", Exception::ILLEGAL_EMAIL, "Email mismatch - more than 255 chars");
		// }
		if ( ! filter_var($email, FILTER_VALIDATE_EMAIL)) {
			throw new Exception("Illegal email", Exception::ILLEGAL_EMAIL, "Email mismatch - not an email");
		}
	}

	/**
	 * Password strength checker - checks password has enough symbols,
	 * and consists of 2 or more character types - small letters, CAPS, numbers and special symbols.
	 *
	 * @param  string $password
	 * @throws Exception If the password is too short
	 * @throws Exception If the password has only one type of chars.
	 */
	protected function checkPassStrength($password)
	{
		if ( ! $password = trim($password)) {
			throw new Exception("Required password is missing", Exception::MISSING_PASSWORD);
		}

		$len = mb_strlen($password, "UTF-8");
		if ($len < 7) {
			throw new Exception("Password must be at least 7 chars", Exception::ILLEGAL_PASSWORD);
		}

		$diff = 0;
		$patterns = array("#[a-z]#", "#[A-Z]#", "#[0-9]#", "#[^a-zA-Z0-9]#");
		foreach ($patterns as $pattern) {
			if (preg_match($pattern, $password, $matches)) {
				$diff++;
			}
		}
		if ($diff < 2) {
			throw new Exception("Password must contain at least 2 different type of chars (lowercase letters, uppercase letters, digits and special symbols)", Exception::ILLEGAL_PASSWORD);
		}
	}

	/**
	 * Checking password confirmation is set and is equal to the password.
	 *
	 * @param  string $password  Password
	 * @param  string $password2 Password confirmation
	 * @throws Exception if password confirmation is missing, or is not equal to the password
	 */
	protected function checkPasswordConfirmation($password, $password2)
	{
		if (!$password2) {
			throw new Exception("Required password confirmation is missing", Exception::MISSING_PASSWORD2);
		}
		// check passwords match
		if ($password2 !== $password) {
			throw new Exception("Password does not match the confirmation", Exception::DIFFERENT_PASSWORD2);
		}
	}

	/**
	 * Persistent token generator. Generates random code.
	 *
	 * @return string
	 */
	protected function genToken()
	{
		$required_length = 128;

		// make it random
		$code = mt_rand() . uniqid(mt_rand(), true) . microtime(true) . mt_rand();
		// SHA-512 produces 128 chars
		// base64_encode for the sha-512 produces 172 chars, 171 without "=".
		$code = trim(base64_encode(hash("sha512", $code)), "=");
		// extract only part of it
		$code = substr($code, mt_rand(0, strlen($code) - $required_length - 1), $required_length);

		return $code;
	}

	/**
	 * Cookie adapter for setting cookies
	 */
	protected function setcookie($name, $value = null, $expire = 0, $path = null, $domain = null, $secure = false, $httponly = false)
	{
		setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);
	}

	/**
	 * Cookie adapter for getting cookies
	 */
	protected function getcookie($name)
	{
		return filter_input(INPUT_COOKIE, $name);
	}
}
