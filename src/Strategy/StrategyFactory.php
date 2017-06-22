<?php
namespace CryptTor\Strategy;

/**
 * Class StrategyFactory
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt\Strategy\Factories
 */
class StrategyFactory
{
    /**
     * Build the strategy method from parameters
     *
     * @param string $strategyString
     * @param string $key
     * @param string $algorithm
     * @param string $mode
     * @return StrategyInterface
     * @throws \Exception
     */
    public function build($strategyString, $key, $algorithm, $mode)
    {
        switch ($strategyString) {
            case OpenSsl::STRATEGY_NAME:
                $cipher = $this->buildOpenSsl($key, $algorithm, $mode);
                break;
            case MCrypt::STRATEGY_NAME:
                $cipher = $this->buildMCrypt($key, $algorithm, $mode);
                break;
            default:
                throw new \Exception(sprintf("%s strategy is not valid", $strategyString));
                break;
        }
        return $cipher;
    }

    /**
     * Build OpenSsl strategy from parameters
     *
     * @param string $key
     * @param string $algorithm
     * @param string $mode
     * @return OpenSsl
     */
    public function buildOpenSsl($key, $algorithm, $mode)
    {
        return new OpenSsl($key, $algorithm, $mode);
    }

    /**
     * Build MCrypt strategy from parameters
     *
     * @param string $key
     * @param string $algorithm
     * @param string $mode
     * @return MCrypt
     */
    public function buildMCrypt($key, $algorithm, $mode)
    {
        return new MCrypt($key, $algorithm, $mode);
    }
}