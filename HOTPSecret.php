<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;


class HOTPSecret
{
	const FORMAT_RAW    = "raw";
	const FORMAT_HEX    = "hex";
	const FORMAT_BASE32 = "base32";

	protected $secret;

	/**
	 * HOTP Secret constructor.
	 *
	 * @param string $secret (optional) The secret token in format specified in the second parameter
	 * @param string $format (optional) The format of the secret token - defaults to raw format
	 */
	public function __construct($secret = null, $format = self::FORMAT_RAW)
	{
		if ($secret !== null) {
			$this->setSecret($secret, $format);
		}
	}

	public function __toString()
	{
		return (string) $this->getSecret();
	}

	/**
	 * Sets a secret token.
	 *
	 * @param string $secret The secret token in format specified in the second parameter
	 * @param [type] $format (optional) The format of the secret token - defaults to raw format
	 */
	public function setSecret($secret, $format = self::FORMAT_RAW)
	{
		if ($format == static::FORMAT_HEX) {
			$secret = hex2bin($secret);
		} elseif ($format == static::FORMAT_BASE32) {
			$secret = $this->base32decode($secret);
		}

		$this->secret = $secret;
	}

	/**
	 * Returns previously set secret token
	 *
	 * @return string
	 */
	public function getSecret()
	{
		return $this->secret;
	}

	/**
	 * Decodes base32 encoded string.
	 * @see SugiPHP\Encode\Base32::decode()
	 *
	 * @param  string $data
	 * @return string
	 */
	protected function base32decode($data)
	{
		$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

		// stringify
		$data = (string) $data;
		if ($data === "") {
			return "";
		}
		// using only uppercase letters
		$data = strtoupper($data);
		// removing trailing "="
		$data = rtrim($data, "=");
		// removing everything that is not part of the alphabet
		$data = preg_replace("~[^{$alphabet}]~", "", $data);

		$binary = "";
		foreach (str_split($data) as $char) {
			$binary .= str_pad(decbin(strpos($alphabet, $char)), 5, 0, STR_PAD_LEFT);
		}
		$binary = substr($binary, 0, (floor(strlen($binary) / 8) * 8));

		$result = "";
		foreach (str_split($binary, 8) as $chunk) {
			$chunk = str_pad($chunk, 8, 0, STR_PAD_RIGHT);
			$result .= chr(bindec($chunk));
		}

		return $result;
	}
}
