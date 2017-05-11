<?php
namespace CryptTor\Strategy;

use CryptTor\Crypt;

/**
 * Class MCrypt
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt\Strategy
 */
class MCrypt implements StrategyInterface
{
    /**
     * MCrypt strategy name
     */
    const STRATEGY_NAME = 'mcrypt';

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var string
     */
    private $mode;

    /**
     * @var string
     */
    private $encryptionKey;

    /**
     * Supported encryption algorithms
     *
     * @var array
     */
    private $supportedAlgorithms = [
        'aes' => 'rijndael-128',
        'blowfish' => 'blowfish',
        'des' => 'des',
        '3des' => 'tripledes',
        'tripledes' => 'tripledes',
        'cast-128' => 'cast-128',
        'cast-256' => 'cast-256',
        'rijndael-128' => 'rijndael-128',
        'rijndael-192' => 'rijndael-192',
        'rijndael-256' => 'rijndael-256',
        'saferplus' => 'saferplus',
        'serpent' => 'serpent',
        'twofish' => 'twofish'
    ];

    /**
     * Supported encryption modes
     *
     * @var array
     */
    private $supportedModes = [
        'cbc' => 'cbc',
        'cfb' => 'cfb',
        'ctr' => 'ctr',
        'ofb' => 'ofb',
        'nofb' => 'nofb',
        'ncfb' => 'ncfb'
    ];

    /**
     * MCrypt constructor.
     * @param string $key
     * @param string $algorithm
     * @param string $mode
     */
    public function __construct(
        $key,
        $algorithm = Crypt::DEFAULT_ENC_ALGO,
        $mode = Crypt::DEFAULT_ENC_MODE
    )
    {
        $this->validateEnvironment();
        $this->setAlgorithm($algorithm);
        $this->setMode($mode);
        $this->setKey($key);
    }

    /**
     * Encrypt string
     *
     * @param string $string
     * @return string
     * @throws \Exception
     */
    public function encrypt($string)
    {
        $ivNumberBytes = $this->getCipherIvLength();
        $iv = $this->getRandomBytes($ivNumberBytes);

        $cipherText = mcrypt_encrypt($this->getCipherAlgorithm(), $this->encryptionKey, $string, $this->mode, $iv );
        if ($cipherText === false) {
            throw new \Exception('Encryption failed');
        }
        return $iv . $cipherText;
    }

    /**
     * Decrypt string
     *
     * @param string $string
     * @return string
     * @throws \Exception
     */
    public function decrypt($string)
    {
        $ivNumberBytes = $this->getCipherIvLength();
        // Extract the initialisation vector and encrypted data
        $iv = substr($string, 0, $ivNumberBytes);
        $cipherText = substr($string, $ivNumberBytes);
        // and decrypt.
        $raw = mcrypt_decrypt($this->getCipherAlgorithm(), $this->encryptionKey, $cipherText, $this->mode, $iv);

        if ($raw === false) {
            throw new \Exception('Decryption failed: ');
        }
        return rtrim($raw, "\0");
    }

    /**
     * Validate environment
     *
     * @throws \Exception
     */
    private function validateEnvironment()
    {
        if ((!extension_loaded('mcrypt')) || (!function_exists('mcrypt_encrypt'))) {
            throw new \Exception('MCrypt extension not loaded');
       }
    }

    /**
     * Generate random bytes
     *
     * @param int $size
     * @return string
     */
    private function getRandomBytes($size)
    {
        return mcrypt_create_iv($size, MCRYPT_DEV_URANDOM);
    }

    /**
     * Get the maximum key size for the selected algorithm and mode of operation
     *
     * @return int
     */
    private function getKeySize()
    {
        return mcrypt_get_key_size($this->supportedAlgorithms[$this->algorithm], $this->supportedModes[$this->mode]);
    }

    /**
     * Get the initialization vector length for the selected algorithm and mode
     *
     * @return int
     */
    private function getCipherIvLength()
    {
        return mcrypt_get_iv_size($this->supportedAlgorithms[$this->algorithm], $this->mode);
    }

    /**
     * Set the encryption algorithm
     *
     * @param string $algorithm
     * @throws \InvalidArgumentException
     */
    private function setAlgorithm($algorithm)
    {
        if (!in_array($algorithm, $this->getSupportedAlgorithms())) {
            throw new \InvalidArgumentException(sprintf(
                'The algorithm %s is not supported by %s',
                $algorithm,
                __CLASS__
            ));
        }
        $this->algorithm = $algorithm;
    }

    /**
     * Set the encryption mode
     *
     * @param $mode
     * @throws \InvalidArgumentException
     */
    private function setMode($mode)
    {
        if (!in_array($mode, $this->getSupportedModes())) {
            throw new \InvalidArgumentException(sprintf(
                'The mode %s is not supported by %s',
                $mode,
                $this->algorithm
            ));
        }
        $this->mode = $mode;
    }

    /**
     * Set the encryption key
     *
     * @param string $key
     * @throws \InvalidArgumentException
     */
    private function setKey($key)
    {
        $keyLen = mb_strlen($key, '8bit');
        if (!$keyLen) {
            throw new \InvalidArgumentException('The key cannot be empty');
        }
        if ($keyLen < $this->getKeySize()) {
            throw new \InvalidArgumentException(sprintf(
                'The size of the key must be at least of %d bytes',
                $this->getKeySize()
            ));
        }

        $this->encryptionKey = $key;
    }


    /**
     * Get the supported algorithms
     *
     * @return array
     */
    private function getSupportedAlgorithms()
    {
        return array_keys($this->supportedAlgorithms);
    }

    /**
     * Get all supported encryption modes
     *
     * @return array
     */
    private function getSupportedModes()
    {
        return array_keys($this->supportedModes);
    }


    /**
     * Get cipher methods
     *
     * @return array
     */
    private function getCipherMethods()
    {
        return mcrypt_list_algorithms();
    }

    /**
     * Get the cipher algorithm
     *
     * @return string
     */
    private function getCipherAlgorithm()
    {
        return strtolower($this->supportedAlgorithms[$this->algorithm]);
    }
}