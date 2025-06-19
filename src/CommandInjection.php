<?php

namespace Wangyihang\VulnerablePhpLib;

class CommandInjection
{
    /**
     * Execute system command directly without any filtering
     * Vulnerability: Direct execution of user input
     * @param string $command Command to execute
     * @return string Command execution result
     */
    public static function level1($command)
    {
        return shell_exec($command);
    }

    /**
     * Execute ping command with only space filtering
     * Vulnerability: Can inject commands using other characters (e.g., ; | &)
     * @param string $host Host to ping
     * @return string Ping result
     */
    public static function level2($host)
    {
        $host = str_replace(' ', '', $host);
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Execute ping command with basic regex filtering
     * Vulnerability: Incomplete regex filtering, can still inject commands
     * @param string $host Host to ping
     * @return string Ping result
     */
    public static function level3($host)
    {
        // Only filter some basic characters, but filtering is incomplete
        $host = preg_replace('/[;&|`$]/', '', $host);
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Execute ping command with domain validation
     * Vulnerability: Domain validation can be bypassed with command injection
     * @param string $host Host to ping
     * @return string Ping result
     */
    public static function level4($host)
    {
        if (!preg_match('/^[a-zA-Z0-9\.-]+$/', $host)) {
            throw new \Exception('Invalid host format');
        }
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Execute ping command with incomplete escaping
     * Vulnerability: Incomplete escaping, can still inject commands
     * @param string $host Host to ping
     * @return string Ping result
     */
    public static function level5($host)
    {
        $host = escapeshellarg($host);
        // Vulnerable because the command is still concatenated
        return shell_exec("ping -c 4 " . $host . " 2>/dev/null");
    }
} 