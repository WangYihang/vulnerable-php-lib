<?php

namespace Wangyihang\VulnerablePhpLib;

class ServerSideRequestFogery
{
    /**
     * Basic SSRF Vulnerability
     * Vulnerability: Direct use of user input URL without any validation
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function level1($url)
    {
        return file_get_contents($url);
    }

    /**
     * SSRF with Protocol Filtering
     * Vulnerability: Only checks if URL starts with http:// or https://
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function level2($url)
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
     * SSRF with IP Filtering
     * Vulnerability: Incomplete IP filtering that can be bypassed
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function level3($url)
    {
        $parsedUrl = parse_url($url);
        $host = $parsedUrl['host'] ?? '';
        
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ip = ip2long($host);
            if ($ip !== false) {
                // Check if it's an internal IP
                if (
                    ($ip >= ip2long('10.0.0.0') && $ip <= ip2long('10.255.255.255')) ||
                    ($ip >= ip2long('172.16.0.0') && $ip <= ip2long('172.31.255.255')) ||
                    ($ip >= ip2long('192.168.0.0') && $ip <= ip2long('192.168.255.255')) ||
                    $ip == ip2long('127.0.0.1')
                ) {
                    return "Internal IP addresses are not allowed";
                }
            }
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
     * SSRF with Redirect Handling
     * Vulnerability: Incomplete redirect handling that can be exploited
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function level4($url)
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

    /**
     * SSRF with Domain Filtering
     * Vulnerability: Incomplete domain filtering that can be bypassed
     * @param string $url URL to fetch
     * @return string URL content
     */
    public static function level5($url)
    {
        $parsedUrl = parse_url($url);
        $host = $parsedUrl['host'] ?? '';
        
        // Incomplete domain filtering
        if (strpos($host, 'internal') !== false || 
            strpos($host, 'local') !== false) {
            return "Internal domains are not allowed";
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
     * SSRF with Response Size Limit
     * Vulnerability: Incomplete response size handling
     * @param string $url URL to fetch
     * @param int $maxSize Maximum response size in bytes
     * @return string URL content
     */
    public static function level6($url, $maxSize = 1048576)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $result = curl_exec($ch);
        curl_close($ch);
        
        // Incomplete size limit implementation
        if (strlen($result) > $maxSize) {
            return "Response too large";
        }
        
        return $result;
    }
} 