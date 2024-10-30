<?php
namespace Aws\Test\Crypto\Polyfill;

use Aws\Crypto\Polyfill\AesGcm;
use Aws\Crypto\Polyfill\Key;
use Aws\Exception\CryptoPolyfillException;
use PHPUnit\Framework\TestCase;

/**
 * Class AesGcmTest
 * @covers Aws\Test\Crypto\Polyfill
 */
class AesGcmTest extends TestCase
{
    public function testEmpty()
    {
        $tag = '';
        $tests = [
            ['58e2fccefa7e3061367f1d57a4e7455a', 128],
            ['cd33b28ac773f74ba00ed1f312572435', 192],
            ['530f8afbc74536b9a963b4f1c4cb738b', 256],
        ];
        foreach ($tests as $t) {
            $ciphertext = AesGcm::encrypt(
                '',
                \str_repeat("\0", 12),
                new Key(\str_repeat("\0", $t[1] >> 3)),
                '',
                $tag,
                $t[1]
            );
            $this->assertSame('', $ciphertext);
            $this->assertSame(
                $t[0],
                bin2hex($tag),
                'Empty test vector failed.'
            );
        }
    }

    /**
     * Test compatibility with OpenSSL
     *
     * @throws \Exception
     */
    public function testCompat()
    {
        $ptLen = \random_int(0, 1024);
        $aadLen = \random_int(0, 1024);

        $tag1 = $tag2 = '';
        for ($i = 0; $i < 16; ++$i) {
            $plaintext = \random_bytes($ptLen + $i);
            $aad = \random_bytes($aadLen + $i);
            $key = \random_bytes(32);
            $nonce = \random_bytes(12);

            $exp = \openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $key,
                OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
                $nonce,
                $tag1,
                $aad
            );
            $got = AesGcm::encrypt(
                $plaintext,
                $nonce,
                new Key($key),
                $aad,
                $tag2
            );
            $this->assertSame(bin2hex($exp), bin2hex($got));
            $this->assertSame(bin2hex($tag1), bin2hex($tag2));
        }
    }
}
