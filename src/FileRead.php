<?php

namespace Wangyihang\VulnerablePhpLib;

class FileRead
{
    /**
     * Basic Path Traversal Vulnerability
     * Vulnerability: Direct use of user input as file path without any validation
     * @param string $path File path to read
     * @return string File contents
     */
    public static function readFileBasic($path)
    {
        return file_get_contents($path);
    }

    /**
     * Medium Difficulty Path Traversal Vulnerability
     * Vulnerability: Basic path validation that can be bypassed using encoded characters
     * @param string $path File path to read
     * @return string File contents
     */
    public static function readFileMedium($path)
    {
        // Simple validation that can be bypassed
        if (strpos($path, '..') !== false) {
            return "Path traversal is not allowed";
        }
        return file_get_contents($path);
    }

    /**
     * Advanced Path Traversal Vulnerability
     * Vulnerability: More complex path validation that can be bypassed using double encoding
     * @param string $path File path to read
     * @return string File contents
     */
    public static function readFileAdvanced($path)
    {
        // More complex validation that can still be bypassed
        $path = urldecode($path);
        if (strpos($path, '..') !== false || strpos($path, '/') === 0) {
            return "Invalid path";
        }
        return file_get_contents($path);
    }

    /**
     * File Read with Incomplete Extension Filtering
     * Vulnerability: Extension filtering that can be bypassed using null bytes or other techniques
     * @param string $path File path to read
     * @return string File contents
     */
    public static function readFileWithExtension($path)
    {
        $extension = pathinfo($path, PATHINFO_EXTENSION);
        $allowedExtensions = ['txt', 'log', 'json'];
        
        if (!in_array($extension, $allowedExtensions)) {
            return "File type not allowed";
        }
        
        return file_get_contents($path);
    }

    /**
     * File Read with Incomplete Directory Restriction
     * Vulnerability: Directory restriction that can be bypassed using path traversal
     * @param string $path File path to read
     * @param string $baseDir Base directory to restrict access
     * @return string File contents
     */
    public static function readFileWithDirectory($path, $baseDir)
    {
        $fullPath = $baseDir . '/' . $path;
        
        // Incomplete directory restriction
        if (strpos($fullPath, $baseDir) !== 0) {
            return "Access denied";
        }
        
        return file_get_contents($fullPath);
    }
} 