<?php

namespace Wangyihang\VulnerablePhpLib;

class SSRF
{
    /**
     * Fetch URL content using file_get_contents without any filtering
     * Vulnerability: Can access any URL, including internal network addresses
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrl($url)
    {
        return file_get_contents($url);
    }

    /**
     * Fetch URL content using curl with only http/https protocol filtering
     * Vulnerability: Can use other protocols like file://, dict://, gopher:// etc.
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrlWithProtocol($url)
    {
        if (strpos($url, 'http://') === 0 || strpos($url, 'https://') === 0) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            $result = curl_exec($ch);
            curl_close($ch);
            return $result;
        }
        return "Invalid protocol";
    }

    /**
     * Fetch URL content using file_get_contents with only localhost filtering
     * Vulnerability: Can use IP addresses or other hostnames to access internal network
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrlWithLocalhostFilter($url)
    {
        if (strpos($url, 'localhost') !== false) {
            return "Access to localhost is not allowed";
        }
        return file_get_contents($url);
    }

    /**
     * Fetch URL content using curl with incomplete IP filtering
     * Vulnerability: IP filtering is incomplete, can use other IP address formats
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrlWithIPFilter($url)
    {
        // Incomplete IP filtering
        if (preg_match('/\b(?:127\.0\.0\.1|localhost)\b/', $url)) {
            return "Access to localhost is not allowed";
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }

    /**
     * Fetch URL content using file_get_contents with incomplete domain filtering
     * Vulnerability: Domain filtering is incomplete, can use other methods to access internal network
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrlWithDomainFilter($url)
    {
        $parsed = parse_url($url);
        if (isset($parsed['host'])) {
            // Incomplete domain filtering
            if (strpos($parsed['host'], 'internal') !== false || 
                strpos($parsed['host'], 'local') !== false) {
                return "Access to internal domains is not allowed";
            }
        }
        return file_get_contents($url);
    }

    /**
     * Fetch URL content using curl with incomplete redirect filtering
     * Vulnerability: Redirect filtering is incomplete, can access internal network through redirects
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function fetchUrlWithRedirect($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        // No redirect target checking
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
} 