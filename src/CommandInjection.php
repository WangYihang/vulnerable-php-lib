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
    public static function executeCommand($command)
    {
        return shell_exec($command);
    }

    /**
     * Execute ping command with only space filtering
     * Vulnerability: Can inject commands using other characters (e.g., ; | &)
     * @param string $host Host to ping
     * @return string Ping result
     */
    public static function pingHost($host)
    {
        $host = str_replace(' ', '', $host);
        return shell_exec("ping -c 4 " . $host);
    }

    /**
     * Execute file find command with partial special character filtering
     * Vulnerability: Incomplete filtering, can still inject commands
     * @param string $filename Filename to search for
     * @return string Search result
     */
    public static function findFile($filename)
    {
        $filename = str_replace([';', '|', '&'], '', $filename);
        return shell_exec("find / -name " . $filename . " 2>/dev/null");
    }

    /**
     * Execute directory listing with improper parameter concatenation
     * Vulnerability: Improper parameter concatenation, can still inject commands
     * @param string $path Path to list contents
     * @return string Directory contents
     */
    public static function listDirectory($path)
    {
        $path = escapeshellarg($path);
        return shell_exec("ls -la " . $path . " 2>/dev/null");
    }

    /**
     * Execute system command with incomplete regex filtering
     * Vulnerability: Incomplete regex filtering, can still inject commands
     * @param string $command Command to execute
     * @return string Command execution result
     */
    public static function executeFilteredCommand($command)
    {
        // Only filter some basic characters, but filtering is incomplete
        $command = preg_replace('/[;&|`$]/', '', $command);
        return shell_exec($command);
    }
} 