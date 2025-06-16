# Vulnerable PHP Library

A PHP library containing vulnerable functions for security testing and educational purposes. This library can be used for:
- Security testing
- Vulnerability scanner testing
- Security training
- Vulnerability research

## Installation

Install via Composer:

```bash
composer require wangyihang/vulnerable-php-lib
```

## Usage

### Command Injection Vulnerabilities

```php
use VulnerablePhpLib\CommandInjection;

// Execute command directly (no filtering)
$result = CommandInjection::executeCommand($_GET['command']);

// Execute ping command (only space filtering)
$result = CommandInjection::pingHost($_GET['host']);

// Execute file find (incomplete filtering)
$result = CommandInjection::findFile($_GET['filename']);

// Execute directory listing (improper parameter concatenation)
$result = CommandInjection::listDirectory($_GET['path']);

// Execute filtered command (incomplete filtering)
$result = CommandInjection::executeFilteredCommand($_GET['command']);
```

### SSRF Vulnerabilities

```php
use VulnerablePhpLib\SSRF;

// Basic SSRF (no filtering)
$result = SSRF::fetchUrl($_GET['url']);

// SSRF with protocol filtering
$result = SSRF::fetchUrlWithProtocol($_GET['url']);

// SSRF with IP filtering
$result = SSRF::fetchUrlWithIPFilter($_GET['url']);

// SSRF with redirect handling
$result = SSRF::fetchUrlWithRedirect($_GET['url']);

// SSRF with domain filtering
$result = SSRF::fetchUrlWithDomain($_GET['url']);

// SSRF with response size limit
$result = SSRF::fetchUrlWithSizeLimit($_GET['url']);
```

### File Read Vulnerabilities

```php
use VulnerablePhpLib\FileRead;

// Basic path traversal
$result = FileRead::readFileBasic($_GET['path']);

// Path traversal with basic validation
$result = FileRead::readFileMedium($_GET['path']);

// Path traversal with advanced validation
$result = FileRead::readFileAdvanced($_GET['path']);

// File read with extension filtering
$result = FileRead::readFileWithExtension($_GET['path']);

// File read with directory restriction
$result = FileRead::readFileWithDirectory($_GET['path'], '/var/www/html');
```

## Security Warning

⚠️ Warning: This library is for security testing and educational purposes only. Do not use these functions in production environments as they contain serious security vulnerabilities.

## License

MIT License 