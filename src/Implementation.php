<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\CryptoInterface;
use fpoirotte\Cryptal\PaddingInterface;

class Implementation implements CryptoInterface
{
    protected $method;
    protected $tagLength;
    protected $padding;
    protected $aead;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct($cipher, $mode, PaddingInterface $padding, $tagLength = 16)
    {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers[$cipher], static::$supportedModes[$mode])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $methods    = openssl_get_cipher_methods();
        $method     = static::$supportedCiphers[$cipher] . '-' . static::$supportedModes[$mode];
        if (!in_array($method, $methods)) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $php71plus  = version_compare(PHP_VERSION, '7.1.0', '>=');
        $aead       = array(
            CryptoInterface::MODE_CCM,
            CryptoInterface::MODE_EAX,
            CryptoInterface::MODE_GCM,
        );

        $this->method       = $method;
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
        $this->aead         = $php71plus && in_array($mode, $aead);
    }

    protected static function checkSupport()
    {
        $modes          = array();
        $ciphers        = array();
        $map            = array(
            'modes'     => array(
                'cbc' => CryptoInterface::MODE_CBC,
                'cfb' => CryptoInterface::MODE_CFB,
                'ctr' => CryptoInterface::MODE_CTR,
                'ecb' => CryptoInterface::MODE_ECB,
                'ocb' => CryptoInterface::MODE_OCB,
                'ofb' => CryptoInterface::MODE_OFB,
            ),
            'ciphers'   => array(
                'des-ede3'      => CryptoInterface::CIPHER_3DES,
                'aes-128'       => CryptoInterface::CIPHER_AES_128,
                'aes-192'       => CryptoInterface::CIPHER_AES_192,
                'aes-256'       => CryptoInterface::CIPHER_AES_256,
                'bf'            => CryptoInterface::CIPHER_BLOWFISH,
                'camelia-128'   => CryptoInterface::CIPHER_CAMELIA_128,
                'camelia-192'   => CryptoInterface::CIPHER_CAMELIA_192,
                'camelia-256'   => CryptoInterface::CIPHER_CAMELIA_256,
                'cast5'         => CryptoInterface::CIPHER_CAST5,
                'des'           => CryptoInterface::CIPHER_DES,
                'rc2'           => CryptoInterface::CIPHER_RC2,
                'rc4'           => CryptoInterface::CIPHER_RC4,
                'seed'          => CryptoInterface::CIPHER_SEED,
            ),
        );

        // The API required to support AEAD was added in PHP 7.1.
        if (version_compare(PHP_VERSION, '7.1.0', '>=')) {
            $map['modes'] += array(
                'ccm' => CryptoInterface::MODE_CCM,
                'eax' => CryptoInterface::MODE_EAX,
                'gcm' => CryptoInterface::MODE_GCM,
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

    public function encrypt($iv, $key, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $options    = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        if ($this->aead) {
            $res = openssl_encrypt($data, $this->method, $key, $options, $iv, $tag, $aad, $this->tagLength);
        } else {
            $res = openssl_encrypt($data, $this->method, $key, $options, $iv);
        }
        return $res;
    }

    public function decrypt($iv, $key, $data, $tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $options    = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        if ($this->aead) {
            $res = openssl_decrypt($data, $this->method, $key, $options, $iv, $tag, $aad);
        } else {
            $res = openssl_decrypt($data, $this->method, $key, $options, $iv);
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
}
