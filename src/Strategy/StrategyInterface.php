<?php
namespace CryptTor\Strategy;

/**
 * Interface StrategyInterface
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt\Strategy
 */
interface StrategyInterface
{
    /**
     * @param string $string
     */
    public function encrypt($string);

    /**
     * @param string $string
     */
    public function decrypt($string);

}