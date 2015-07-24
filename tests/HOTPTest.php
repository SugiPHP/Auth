<?php
/**
 * @package  SugiPHP.Auth
 * @category tests
 * @author   Plamen Popov <tzappa@gmail.com>
 * @license  http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Auth;

/**
 *
 *
 * RFC 4226                     HOTP Algorithm                December 2005
 *
 *
 * Appendix D - HOTP Algorithm: Test Values
 *
 *    The following test data uses the ASCII string
 *    "12345678901234567890" for the secret:
 *
 *    Secret = 0x3132333435363738393031323334353637383930
 *
 *    Table 1 details for each count, the intermediate HMAC value.
 *
 *    Count    Hexadecimal HMAC-SHA-1(secret, count)
 *    0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
 *    1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
 *    2        0bacb7fa082fef30782211938bc1c5e70416ff44
 *    3        66c28227d03a2d5529262ff016a1e6ef76557ece
 *    4        a904c900a64b35909874b33e61c5938a8e15ed1c
 *    5        a37e783d7b7233c083d4f62926c7a25f238d0316
 *    6        bc9cd28561042c83f219324d3c607256c03272ae
 *    7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
 *    8        1b3c89f65e6c9e883012052823443f048b4332db
 *    9        1637409809a679dc698207310c8c7fc07290d9e5
 *
 *    Table 2 details for each count the truncated values (both in
 *    hexadecimal and decimal) and then the HOTP value.
 *
 *                      Truncated
 *    Count    Hexadecimal    Decimal        HOTP
 *    0        4c93cf18       1284755224     755224
 *    1        41397eea       1094287082     287082
 *    2         82fef30        137359152     359152
 *    3        66ef7655       1726969429     969429
 *    4        61c5938a       1640338314     338314
 *    5        33c083d4        868254676     254676
 *    6        7256c032       1918287922     287922
 *    7         4e5b397         82162583     162583
 *    8        2823443f        673399871     399871
 *    9        2679dc69        645520489     520489
 *
 */

class HOTPTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructNoParams()
    {
        $this->setExpectedException("PHPUnit_Framework_Error");
        $hotp = new HOTP();
    }

    public function testGen()
    {
        $hotp = new HOTP(new HOTPSecret("3132333435363738393031323334353637383930", HOTPSecret::FORMAT_HEX));
        $this->assertSame("755224", $hotp->gen(0));
        $this->assertSame("287082", $hotp->gen(1));
        $this->assertSame("359152", $hotp->gen(2));
        $this->assertSame("969429", $hotp->gen(3));
        $this->assertSame("338314", $hotp->gen(4));
        $this->assertSame("254676", $hotp->gen(5));
        $this->assertSame("287922", $hotp->gen(6));
        $this->assertSame("162583", $hotp->gen(7));
        $this->assertSame("399871", $hotp->gen(8));
        $this->assertSame("520489", $hotp->gen(9));
    }

    public function testGen8Digits()
    {
        $hotp = new HOTP(new HOTPSecret("3132333435363738393031323334353637383930", HOTPSecret::FORMAT_HEX), 8);
        $this->assertSame("84755224", $hotp->gen(0));
        $this->assertSame("94287082", $hotp->gen(1));
        $this->assertSame("37359152", $hotp->gen(2));
        $this->assertSame("26969429", $hotp->gen(3));
        $this->assertSame("40338314", $hotp->gen(4));
        $this->assertSame("68254676", $hotp->gen(5));
        $this->assertSame("18287922", $hotp->gen(6));
        $this->assertSame("82162583", $hotp->gen(7));
        $this->assertSame("73399871", $hotp->gen(8));
        $this->assertSame("45520489", $hotp->gen(9));
    }

    public function testCheck0()
    {
        $hotp = new HOTP(new HOTPSecret("3132333435363738393031323334353637383930", HOTPSecret::FORMAT_HEX));
        $this->assertSame(-1, $hotp->check("359152", 0, 0));
        $this->assertSame(-1, $hotp->check("359152", 1, 0));
        $this->assertSame(0, $hotp->check("359152", 2, 0));
        $this->assertSame(-1, $hotp->check("359152", 3, 0));
        $this->assertSame(-1, $hotp->check("359152", 4, 0));
        $this->assertSame(-1, $hotp->check("359152", 5, 0));
    }

    public function testCheck1()
    {
        $hotp = new HOTP(new HOTPSecret("3132333435363738393031323334353637383930", HOTPSecret::FORMAT_HEX));
        $this->assertSame(-1, $hotp->check("359152", 0, 1));
        $this->assertSame(1, $hotp->check("359152", 1, 1));
        $this->assertSame(0, $hotp->check("359152", 2, 1));
        $this->assertSame(-1, $hotp->check("359152", 3, 1));
        $this->assertSame(-1, $hotp->check("359152", 4, 1));
        $this->assertSame(-1, $hotp->check("359152", 5, 1));
    }
}
