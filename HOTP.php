<?php
/**
 * @package SugiPHP.Auth
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

/**
 * HOTP: An HMAC-Based One-Time Password Algorithm
 * @see http://www.ietf.org/rfc/rfc4226.txt
 * TOTP: Time-Based One-Time Password Algorithm
 * @see http://www.ietf.org/rfc/rfc6238.txt
 */
class HOTP
{
    protected $digits = 6;
    protected $secret;

    public function __construct($secret, $digits = 6)
    {
        $this->secret = (string) $secret;
        $this->digits = $digits;
    }

    public function gen($counter)
    {
        $digits = $this->digits;
        $secret = $this->secret;
        $counter = $this->counterToString($counter);

        $hash = hash_hmac("sha1", $counter, $secret, true);

        $otp = $this->truncateHash($hash);
        if ($digits < 10) {
            $otp %= pow(10, $digits);
        }

        return str_pad($otp, $digits, "0", STR_PAD_LEFT);
    }

    public function check($otp, $counter, $window = 5)
    {
        $counter = max(0, $counter);

        $offset = -1;
        for ($i = $counter; $i <= $counter + $window; $i++) {
            if ($otp == $this->gen($i)) {
                $offset = $i - $counter;
                break;
            }
        }

        return $offset;
    }

    /**
     * Extract 4 bytes from a hash value
     * Uses the method defined in RFC 4226 section 5.4
     *
     * @param  string $hash
     * @return integer
     */
    protected function truncateHash($hash)
    {
        $offset = ord($hash[19]) & 0xf;
        $value = (ord($hash[$offset + 0]) & 0x7f) << 24;
        $value |= (ord($hash[$offset + 1]) & 0xff) << 16;
        $value |= (ord($hash[$offset + 2]) & 0xff) << 8;
        $value |= (ord($hash[$offset + 3]) & 0xff);

        return $value;
    }

    /**
     * Convert an integer counter into a string of 8 bytes.
     *
     * @param  integer $counter The counter value
     * @return string Returns an 8-byte binary string
     */
    protected function counterToString($counter)
    {
        $tmp = "";
        while ($counter != 0) {
            $tmp .= chr($counter & 0xff);
            $counter >>= 8;
        }

        return substr(str_pad(strrev($tmp), 8, "\0", STR_PAD_LEFT), 0, 8);
    }
}
