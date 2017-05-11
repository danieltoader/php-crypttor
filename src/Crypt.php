<?php
namespace CryptTor;

use CryptTor\Strategy\StrategyInterface;

/**
 * Class Crypt
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt
 */
class Crypt
{
    /**
     * Default encoding cipher algorithm
     */
    const DEFAULT_ENC_ALGO = 'aes';

    /**
     * Default encoding cipher mode
     */
    const DEFAULT_ENC_MODE = 'cbc';

    /**
     * Output/input format. Available options: FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     * @var int
     */
    private $format;

    /**
     * @var StrategyInterface
     */
    private $strategy;

    /**
     * Crypt constructor.
     * @param StrategyInterface $cipher
     * @param int $format
     */
    public function __construct(
        StrategyInterface $cipher,
        $format = Format::FORMAT_B64
    )
    {
        $this->setStrategy($cipher);
        $this->setFormat($format);
    }

    /**
     * Encrypt data
     *
     * @param string $data
     * @return string
     * @throws \InvalidArgumentException
     */
    public function encrypt($data)
    {
        $this->validateData($data);
        $rawData = $this->strategy->encrypt($data);
        return Format::output($rawData, $this->format);
    }

    /**
     * Decrypt data
     *
     * @param string $data
     * @return string
     * @throws \InvalidArgumentException
     */
    public function decrypt($data)
    {
        $this->validateData($data);
        $rawData = Format::input($data, $this->format);
        return $this->strategy->decrypt($rawData);
    }

    /**
     * Set strategy method
     *
     * @param StrategyInterface $cipher
     */
    private function setStrategy(StrategyInterface $cipher)
    {
        $this->strategy = $cipher;
    }

    /**
     * Set output/input format. Available options: FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     *
     * @param int $format
     * @throws \InvalidArgumentException
     */
    private function setFormat($format)
    {
        Format::validate($format);
        $this->format = $format;
    }

    /**
     * Validate encrypt/decrypt data
     *
     * @param string $data
     * @throws \InvalidArgumentException
     */
    private function validateData($data)
    {
        if (false === is_string($data)) {
            throw new \InvalidArgumentException('Data parameter must be a string');
        }
        if ('' === $data) {
            throw new \InvalidArgumentException('Data parameter cannot be empty');
        }
    }
}
