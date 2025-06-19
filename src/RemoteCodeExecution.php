<?php

namespace Wangyihang\VulnerablePhpLib;

class RemoteCodeExecution
{
    /**
     * Execute a system command and capture stdout and stderr.
     * Throws exception on non-zero exit code with stderr message.
     *
     * @param string $command
     * @return string
     * @throws \RuntimeException
     */
    private static function executeCommand($command)
    {
        $descriptorspec = [
            1 => ['pipe', 'w'], // stdout
            2 => ['pipe', 'w'], // stderr
        ];
        $process = proc_open($command, $descriptorspec, $pipes);
        if (!is_resource($process)) {
            throw new \RuntimeException('Could not start process');
        }
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $return_value = proc_close($process);
        if ($return_value !== 0) {
            throw new \RuntimeException("Command($command) execution failed (exit code $return_value): $stderr");
        }
        return $stdout;
    }

    /**
     * Executes a system command directly without any filtering.
     *
     * @param string $command The command to execute (user input is executed directly).
     * @return string|false The result of the command execution, or false on failure.
     * @vulnerability Direct command execution of user input (command injection).
     */
    public static function level1($command)
    {
        return self::executeCommand($command);
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
        return self::executeCommand("ping -c 1 " . $host);
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
        $host = preg_replace('/[;&|`$]/', '', $host);
        return self::executeCommand("ping -c 1 " . $host);
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
        return self::executeCommand("ping -c 1 " . $host);
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
        return self::executeCommand("ping -c 1 " . $host . " 2>/dev/null");
    }
} 