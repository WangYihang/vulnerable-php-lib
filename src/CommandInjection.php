<?php

namespace Wangyihang\VulnerablePhpLib;

class CommandInjection
{
    /**
     * Executes a system command directly without any filtering.
     *
     * @param string $command The command to execute (user input is executed directly).
     * @return string|false The result of the command execution, or false on failure.
     * @vulnerability Direct command execution of user input (command injection).
     */
    public static function level1($command)
    {
        return shell_exec($command);
    }

    /**
     * Executes a ping command after removing spaces from the host.
     *
     * @param string $host The host to ping (spaces are removed, but other injection vectors remain).
     * @return string|false The result of the ping command, or false on failure.
     * @vulnerability Space is filtered, but other special characters (e.g., ; | &) can still be used for command injection.
     */
    public static function level2($host)
    {
        $host = str_replace(' ', '', $host);
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Executes a ping command after basic regex filtering of some special characters.
     *
     * @param string $host The host to ping (filters ; & | ` $ but not all dangerous characters).
     * @return string|false The result of the ping command, or false on failure.
     * @vulnerability Incomplete regex filtering; command injection is still possible with unfiltered characters.
     */
    public static function level3($host)
    {
        // Only filter some basic characters, but filtering is incomplete
        $host = preg_replace('/[;&|`$]/', '', $host);
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Executes a ping command after validating the host with a domain regex.
     *
     * @param string $host The host to ping (must match /^[a-zA-Z0-9\.-]+$/).
     * @return string|false The result of the ping command, or false on failure.
     * @throws \Exception If the host format is invalid.
     * @vulnerability Regex validation can be bypassed if not strict enough; command injection may still be possible.
     */
    public static function level4($host)
    {
        if (!preg_match('/^[a-zA-Z0-9\.-]+$/', $host)) {
            throw new \Exception('Invalid host format');
        }
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Executes a ping command after escaping the host argument.
     *
     * @param string $host The host to ping (escapeshellarg is used, but command is still concatenated).
     * @return string|false The result of the ping command, or false on failure.
     * @vulnerability Incomplete escaping; command injection may still be possible depending on context.
     */
    public static function level5($host)
    {
        $host = escapeshellarg($host);
        // Vulnerable because the command is still concatenated
        return shell_exec("ping -c 4 " . $host . " 2>/dev/null");
    }
} 