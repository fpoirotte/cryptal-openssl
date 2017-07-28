<?php

namespace fpoirotte\Cryptal\Plugins\Openssl;

use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\Implementers\HashInterface;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\HashEnum;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Hash extends HashInterface implements PluginInterface
{
    private $data;
    protected $method;
    protected static $supportedAlgos = null;

    public function __construct(HashEnum $algorithm)
    {
        if (static::$supportedAlgos === null) {
            static::checkSupport();
        }

        $this->method = $algorithm;
    }

    protected static function checkSupport()
    {
        $supported  = array(
            (string) HashEnum::HASH_MD2()       => 'md2',
            (string) HashEnum::HASH_MD4()       => 'md4',
            (string) HashEnum::HASH_MD5()       => 'md5',
            (string) HashEnum::HASH_RIPEMD160() => 'ripemd160',
            (string) HashEnum::HASH_SHA1()      => 'sha1',
            (string) HashEnum::HASH_SHA224()    => 'sha224',
            (string) HashEnum::HASH_SHA256()    => 'sha256',
            (string) HashEnum::HASH_SHA384()    => 'sha384',
            (string) HashEnum::HASH_SHA512()    => 'sha512',
        );

        static::$supportedAlgos     = array_intersect($supported, openssl_get_md_methods(false));
    }

    protected function internalUpdate($data)
    {
        $this->data .= $data;
    }

    protected function internalFinish()
    {
        return openssl_digest($this->data, $this->method, true);
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        static::checkSupport();
        foreach (static::$supportedAlgos as $algo => $algoConst) {
            $registry->addHash(
                __CLASS__,
                HashEnum::$algo(),
                ImplementationTypeEnum::TYPE_COMPILED()
            );
        }
    }
}
