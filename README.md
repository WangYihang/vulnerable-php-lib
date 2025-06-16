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

// Fetch URL content directly (no filtering)
$result = SSRF::fetchUrl($_GET['url']);

// Fetch URL content (only protocol filtering)
$result = SSRF::fetchUrlWithProtocol($_GET['url']);

// Fetch URL content (only localhost filtering)
$result = SSRF::fetchUrlWithLocalhostFilter($_GET['url']);

// Fetch URL content (incomplete IP filtering)
$result = SSRF::fetchUrlWithIPFilter($_GET['url']);

// Fetch URL content (incomplete domain filtering)
$result = SSRF::fetchUrlWithDomainFilter($_GET['url']);

// Fetch URL content (incomplete redirect filtering)
$result = SSRF::fetchUrlWithRedirect($_GET['url']);
```

## Security Warning

⚠️ Warning: This library is for security testing and educational purposes only. Do not use these functions in production environments as they contain serious security vulnerabilities.

## License

MIT License 