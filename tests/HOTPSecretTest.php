<?php
/**
 * @package    SugiPHP
 * @subpackage Auth
 * @category   tests
 * @author     Plamen Popov <tzappa@gmail.com>
 * @license    http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

class HOTPSecretTest extends \PHPUnit_Framework_TestCase
{
	public function testConstructNoParams()
	{
		$secret = new HOTPSecret();
		$this->assertSame("", $secret->__toString());
		$this->assertNull($secret->getSecret());
	}
}
