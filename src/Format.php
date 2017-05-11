<?php

namespace CryptTor;

/**
 * Class Format
 *
 * @author Daniel Toader <developer@danieltoader.com>
 * @package Crypt
 */
class Format
{
    /**
     * Process input/output string in raw format
     */
    const FORMAT_RAW = 0;

    /**
     * Process input/output string in base64 format
     */
    const FORMAT_B64 = 1;

    /**
     * Process input/output string in hexadecimal format
     */
    const FORMAT_HEX = 2;

    /**
     * Format the output string
     *
     * @param string $string
     * @param int $format
     * @return string
     */
    public static function output($string, $format)
    {
        if ($format == self::FORMAT_B64) {
            $string = base64_encode($string);
        } elseif ($format == self::FORMAT_HEX) {
            $string = unpack('H*', $string)[1];
        }
        return $string;
    }

    /**
     * Format the input string
     *
     * @param string $string
     * @param int $format
     * @return string
     */
    public static function input($string, $format)
    {
        if ($format == self::FORMAT_B64) {
            $string = base64_decode($string);
        } elseif ($format == self::FORMAT_HEX) {
            $string = pack('H*', $string);
        }
        return $string;
    }

    /**
     * Validate that format is one of the following FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     *
     * @param int $format
     */
    public static function validate($format)
    {
        if(!in_array($format, [self::FORMAT_RAW, self::FORMAT_B64, self::FORMAT_HEX])){
            throw new \InvalidArgumentException('Format not valid');
        }
    }
}