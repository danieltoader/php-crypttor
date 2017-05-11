<?php
namespace CryptTor;

use CryptTor\Strategy\StrategyFactory;
use CryptTor\Strategy\OpenSsl;
use CryptTor\Strategy\StrategyInterface;

/**
 * Crypt Facade
 *
 * Class CryptService
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt
 */
class CryptService
{
    /**
     * @var StrategyFactory
     */
    private static $strategyFactory;

    /**
     * @return StrategyFactory
     */
    private static function getStrategyFactory()
    {
        if (! static::$strategyFactory instanceof StrategyFactory) {
            static::$strategyFactory = new StrategyFactory();
        }
        return static::$strategyFactory;
    }

    /**
     * @param string $string
     * @param string $key
     * @param string $strategyString
     * @param int $format
     * @param string $algorithm
     * @param string $mode
     * @return string
     */
    public static function encrypt(
        $string,
        $key,
        $strategyString = OpenSsl::STRATEGY_NAME,
        $format = Format::FORMAT_RAW,
        $algorithm = Crypt::DEFAULT_ENC_ALGO,
        $mode = Crypt::DEFAULT_ENC_MODE
    )
    {
        $strategy = static::getStrategyFactory()->build($strategyString, $key, $algorithm, $mode);
        return (new Crypt($strategy, $format))->encrypt($string);
    }

    /**
     * @param string $string
     * @param string $key
     * @param string $strategyString
     * @param int $format
     * @param string $algorithm
     * @param string $mode
     * @return string
     */
    public static function decrypt(
        $string,
        $key,
        $strategyString = OpenSsl::STRATEGY_NAME,
        $format = Format::FORMAT_RAW,
        $algorithm = Crypt::DEFAULT_ENC_ALGO,
        $mode = Crypt::DEFAULT_ENC_MODE
    )
    {
        $strategy = static::getStrategyFactory()->build($strategyString, $key, $algorithm, $mode);
        return (new Crypt($strategy, $format))->decrypt($string);
    }
}