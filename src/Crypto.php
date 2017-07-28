<?php

namespace fpoirotte\Cryptal\Plugins\Openssl;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Crypto implements CryptoInterface, PluginInterface
{
    protected $method;
    protected $tagLength;
    protected $padding;
    protected $aead;
    protected $cipher;
    private $key;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers["$cipher"], static::$supportedModes["$mode"])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $methods    = openssl_get_cipher_methods();
        $method     = static::$supportedCiphers["$cipher"] . '-' . static::$supportedModes["$mode"];
        if (!in_array($method, $methods)) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $php71plus  = version_compare(PHP_VERSION, '7.1.0', '>=');
        $aead       = array(
            ModeEnum::MODE_CCM(),
            ModeEnum::MODE_EAX(),
            ModeEnum::MODE_GCM(),
        );

        $this->method       = $method;
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
        $this->aead         = $php71plus && in_array($mode, $aead);
        $this->cipher       = $cipher;
        $this->key          = $key;
    }

    protected static function checkSupport()
    {
        $modes          = array();
        $ciphers        = array();
        $map            = array(
            'modes'     => array(
                'cbc' => (string) ModeEnum::MODE_CBC(),
                'cfb' => (string) ModeEnum::MODE_CFB(),
                'ctr' => (string) ModeEnum::MODE_CTR(),
                'ecb' => (string) ModeEnum::MODE_ECB(),
                'ocb' => (string) ModeEnum::MODE_OCB(),
                'ofb' => (string) ModeEnum::MODE_OFB(),
            ),
            'ciphers'   => array(
                'des-ede3'      => (string) CipherEnum::CIPHER_3DES(),
                'aes-128'       => (string) CipherEnum::CIPHER_AES_128(),
                'aes-192'       => (string) CipherEnum::CIPHER_AES_192(),
                'aes-256'       => (string) CipherEnum::CIPHER_AES_256(),
                'bf'            => (string) CipherEnum::CIPHER_BLOWFISH(),
                'camelia-128'   => (string) CipherEnum::CIPHER_CAMELIA_128(),
                'camelia-192'   => (string) CipherEnum::CIPHER_CAMELIA_192(),
                'camelia-256'   => (string) CipherEnum::CIPHER_CAMELIA_256(),
                'cast5'         => (string) CipherEnum::CIPHER_CAST5(),
                'des'           => (string) CipherEnum::CIPHER_DES(),
                'rc2'           => (string) CipherEnum::CIPHER_RC2(),
                'rc4'           => (string) CipherEnum::CIPHER_RC4(),
                'seed'          => (string) CipherEnum::CIPHER_SEED(),
            ),
        );

        // The API required to support AEAD was added in PHP 7.1.
        if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
            $map['modes'] += array(
                'ccm' => (string) ModeEnum::MODE_CCM(),
                'eax' => (string) ModeEnum::MODE_EAX(),
                'gcm' => (string) ModeEnum::MODE_GCM(),
            );
        }

        foreach (openssl_get_cipher_methods(false) as $method) {
            $mode   = substr(strrchr($method, '-'), 1);
            $cipher = substr($method, 0, -(strlen($mode) + 1));

            $modes[$mode]       = 1;
            $ciphers[$cipher]   = 1;
        }

        static::$supportedModes     = array_flip(array_intersect_key($map['modes'], $modes));
        static::$supportedCiphers   = array_flip(array_intersect_key($map['ciphers'], $ciphers));
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $options    = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        if ($this->aead) {
            $res = openssl_encrypt($data, $this->method, $this->key, $options, $iv, $tag, $aad, $this->tagLength);
        } else {
            $res = openssl_encrypt($data, $this->method, $this->key, $options, $iv);
        }
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $options    = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        if ($this->aead) {
            $res = openssl_decrypt($data, $this->method, $this->key, $options, $iv, $tag, $aad);
        } else {
            $res = openssl_decrypt($data, $this->method, $this->key, $options, $iv);
        }
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        $res = openssl_cipher_iv_length($this->method);
        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public function getBlockSize()
    {
        // To compute the block size, we simply encode an empty string
        // using an empty key. OpenSSL will expand the key for us and
        // will return a PKCS#7-padded ciphertext.
        // Since the original plaintext was empty, the output's size
        // matches the block size.
        $iv     = str_repeat('a', $this->getIVSize());
        $tag    = null;
        if ($this->aead) {
            $res = openssl_encrypt('', $this->method, '', OPENSSL_RAW_DATA, $iv, $tag, '', $this->tagLength);
        } else {
            $res = openssl_encrypt('', $this->method, '', OPENSSL_RAW_DATA, $iv);
        }

        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }

        return strlen($res);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedModes as $mode => $modeConst) {
            foreach (static::$supportedCiphers as $cipher => $cipherConst) {
                $registry->addCipher(
                    __CLASS__,
                    CipherEnum::$cipher(),
                    ModeEnum::$mode(),
                    ImplementationTypeEnum::TYPE_COMPILED()
                );
            }
        }
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
