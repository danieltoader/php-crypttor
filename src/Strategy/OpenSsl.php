<?php
namespace CryptTor\Strategy;

use CryptTor\Crypt;

/**
 * Class OpenSsl
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt\Strategy
 */
class OpenSsl implements StrategyInterface
{
    /**
     * OpenSSL strategy name
     */
    const STRATEGY_NAME = 'openssl';

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
        'aes' => 'aes-256',
        'blowfish' => 'bf',
        'des' => 'des',
        'camellia' => 'camellia-256',
        'cast5' => 'cast5',
        'seed' => 'seed',
    ];

    /**
     * Supported encryption modes
     *
     * @var array
     */
    private $supportedModes = [
        'cbc' => 'cbc',
        'cfb' => 'cfb',
        'ofb' => 'ofb',
        'ecb' => 'ecb'
    ];

    /**
     * Key sizes (in bytes) for each supported algorithm
     *
     * @var array
     */
    private $keySizes = [
        'aes' => 32,
        'blowfish' => 56,
        'des' => 8,
        'camellia' => 32,
        'cast5' => 16,
        'seed' => 16,
    ];

    /**
     * OpenSsl constructor.
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

        $opts = OPENSSL_RAW_DATA;
        $cipherText = openssl_encrypt($string, $this->getCipherAlgorithm(), $this->encryptionKey, $opts, $iv);
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
        $opts = OPENSSL_RAW_DATA;
        $raw = openssl_decrypt($cipherText, $this->getCipherAlgorithm(), $this->encryptionKey, $opts, $iv);

        if ($raw === false) {
            throw new \Exception('Decryption failed: ');
        }
        return $raw;
    }

    /**
     * Validate environment
     *
     * @throws \Exception
     */
    private function validateEnvironment()
    {
        if (!(extension_loaded('openssl')) || (!function_exists('openssl_encrypt'))) {
            throw new \Exception('OpenSSL extension not loaded');
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
        return openssl_random_pseudo_bytes($size);
    }

    /**
     * Get the key size for the selected algorithm
     *
     * @return int
     */
    private function getKeySize()
    {
        return $this->keySizes[$this->algorithm];
    }

    /**
     * Get the initialization vector length for the selected algorithm
     *
     * @return int
     */
    private function getCipherIvLength()
    {
        return openssl_cipher_iv_length($this->getCipherAlgorithm());
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
     * @param string $mode
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
        if (empty($this->supportedAlgorithms)) {
            foreach ($this->supportedAlgorithms as $name => $algo) {
                // CBC mode is supported by all the algorithms
                if (in_array($this->supportedAlgorithms[$algo] . '-cbc', $this->getSupportedModes())) {
                    $this->supportedAlgorithms[] = $name;
                }
            }
        }
        return array_keys($this->supportedAlgorithms);
    }

    /**
     * Get all supported encryption modes for the selected algorithm
     *
     * @return array
     */
    private function getSupportedModes()
    {
        $modes = [];
        foreach ($this->supportedModes as $mode) {
            $algo = $this->supportedAlgorithms[$this->algorithm] . '-' . $mode;
            if (in_array($algo, $this->getCipherMethods())) {
                $modes[] = $mode;
            }
        }
        return $modes;
    }

    /**
     * Get cipher methods
     *
     * @param bool $aliases
     * @return array
     */
    private function getCipherMethods($aliases = true)
    {
        return openssl_get_cipher_methods($aliases);
    }

    /**
     * Get the cipher algorithm
     *
     * @return string
     */
    private function getCipherAlgorithm()
    {
        return strtolower($this->supportedAlgorithms[$this->algorithm] . '-' . $this->mode);
    }
}