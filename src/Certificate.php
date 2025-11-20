<?php

namespace DazzaDev\DgtCrSigner;

use DazzaDev\DgtCrSigner\Exceptions\CertificateException;
use DazzaDev\DgtCrSigner\Exceptions\UnsupportedPkcs12Exception;

class Certificate
{
    /**
     * Path to the certificate file
     */
    protected string $certificatePath;

    /**
     * Password for the certificate file
     */
    protected string $certificatePassword;

    /**
     * Certificate data array
     */
    protected array $certificateData = [];

    /**
     * Certificate PEM data
     */
    protected string $certificatePem = '';

    /**
     * Certificate content
     */
    protected string $certificateContent = '';

    /**
     * Certificate object array
     */
    protected array $certificateObject = [];

    /**
     * Private key PEM data
     */
    protected string $privateKeyPem = '';

    /**
     * Private key data array
     */
    protected array $privateKeyData = [];

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $certificatePassword)
    {
        $this->certificatePath = $certificatePath;
        $this->certificatePassword = $certificatePassword;
        $this->loadCertificate();
    }

    /**
     * Returns certificate data
     */
    public function getCertificateData(): array
    {
        return $this->certificateData;
    }

    /**
     * Returns certificate PEM data
     */
    public function getCertificatePem(): string
    {
        return $this->certificatePem;
    }

    /**
     * Returns certificate content
     */
    public function getCertificateContent(): string
    {
        return $this->certificateContent;
    }

    /**
     * Returns certificate object
     */
    public function getCertificateObject(): array
    {
        return $this->certificateObject;
    }

    /**
     * Returns private key PEM data
     */
    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * Returns private key data
     */
    public function getPrivateKeyData(): array
    {
        return $this->privateKeyData;
    }

    /**
     * Returns issuer name from certificate object
     */
    public function getIssuerName(): string
    {
        return $this->certificateObject['issuer'] ?? '';
    }

    /**
     * Returns subject name from certificate object
     */
    public function getSubjectName(): string
    {
        return $this->certificateObject['subject'] ?? '';
    }

    /**
     * Returns serial number from certificate object
     */
    public function getSerialNumber(): string
    {
        return $this->certificateObject['serialNumber'] ?? '';
    }

    /**
     * Returns modulus from certificate object
     */
    public function getModulus(): string
    {
        return $this->privateKeyData['modulus'] ?? '';
    }

    /**
     * Returns exponent from certificate object
     */
    public function getExponent(): string
    {
        return $this->privateKeyData['exponent'] ?? '';
    }

    /**
     * Loads certificate data from PKCS#12 file
     */
    protected function loadCertificate(): void
    {
        $p12FileData = file_exists($this->certificatePath) ? file_get_contents($this->certificatePath) : '';

        if ($p12FileData === false || $p12FileData === '') {
            throw new UnsupportedPkcs12Exception('PKCS#12 file not found or unreadable at: '.$this->certificatePath);
        }

        $this->certificateData = $this->extractPrivateKeyAndCertificateFromPkcs12($p12FileData);
    }

    /**
     * Gets all certificates from PKCS#12 file using CLI
     */
    protected function getAllCertificatesFromPkcs12(string $pkcs12FilePath): array
    {
        $passwordArg = $this->certificatePassword ? '-passin pass:'.escapeshellarg($this->certificatePassword) : '-passin pass:';

        // Get all certificates
        $command = 'openssl pkcs12 -in '.escapeshellarg($pkcs12FilePath).' -nokeys -clcerts '.$passwordArg;
        $certOutput = $this->executeOpenSslCommand($command);

        // Parse certificates using regex to properly extract PEM blocks
        $certificates = [];
        $pattern = '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s';

        if (preg_match_all($pattern, $certOutput, $matches)) {
            foreach ($matches[0] as $cert) {
                // Clean up the certificate block
                $cert = trim($cert);

                // Get certificate subject to extract friendly name
                $tempFile = tempnam(sys_get_temp_dir(), 'cert_');
                file_put_contents($tempFile, $cert);

                try {
                    $subjectCommand = 'openssl x509 -in '.escapeshellarg($tempFile).' -noout -subject';
                    $subject = $this->executeOpenSslCommand($subjectCommand);

                    $certificates[] = [
                        'certificate' => $cert,
                        'subject' => $subject,
                        'friendlyName' => $this->extractFriendlyNameFromSubject($subject),
                    ];
                } catch (UnsupportedPkcs12Exception $e) {
                    // Skip invalid certificates
                    continue;
                } finally {
                    unlink($tempFile);
                }
            }
        }

        return $certificates;
    }

    /**
     * Gets all private keys from PKCS#12 file using CLI
     */
    protected function getAllPrivateKeysFromPkcs12(string $pkcs12FilePath): array
    {
        $passwordArg = $this->certificatePassword ? '-passin pass:'.escapeshellarg($this->certificatePassword) : '-passin pass:';

        // Get all private keys
        $command = 'openssl pkcs12 -in '.escapeshellarg($pkcs12FilePath).' -nocerts -nodes '.$passwordArg;
        $keyOutput = $this->executeOpenSslCommand($command);

        // Parse private keys using regex to properly extract PEM blocks
        $privateKeys = [];
        $pattern = '/-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----/s';

        if (preg_match_all($pattern, $keyOutput, $matches)) {
            foreach ($matches[0] as $key) {
                // Clean up the private key block
                $key = trim($key);

                // Extract friendly name from the output if present
                $friendlyName = '';
                if (preg_match('/friendlyName:\s*(.+)/', $keyOutput, $friendlyMatches)) {
                    $friendlyName = trim($friendlyMatches[1]);
                }

                $privateKeys[] = [
                    'privateKey' => $key,
                    'friendlyName' => $friendlyName,
                ];
            }
        }

        return $privateKeys;
    }

    /**
     * Extracts friendly name from certificate subject
     */
    protected function extractFriendlyNameFromSubject(string $subject): string
    {
        // Try to extract CN (Common Name) as friendly name
        if (preg_match('/CN\s*=\s*([^,]+)/', $subject, $matches)) {
            return trim($matches[1]);
        }

        return '';
    }

    /**
     * Extracts issuer data from certificate in the format expected by SRI
     */
    protected function formatIssuer(array $issuer): string
    {
        // Convert issuer array to key-value pairs and reverse order
        $issuerAttrs = [];
        foreach ($issuer as $shortName => $value) {
            // Normalize the short name
            $issuerAttrs[] = ['shortName' => $shortName, 'value' => $value];
        }

        // Reverse the array and map to "shortName=value" format
        $issuerName = array_map(function ($attr) {
            return $attr['shortName'].'='.$attr['value'];
        }, array_reverse($issuerAttrs));

        return implode(',', $issuerName);
    }

    /**
     * Parse certificate PEM to extract structured information similar to JavaScript forge object
     */
    protected function extractCertificateObject(): array
    {
        // Parse certificate using openssl_x509_parse
        $certDetails = openssl_x509_parse($this->certificatePem);
        if ($certDetails === false) {
            throw new CertificateException('Unable to parse certificate');
        }

        // Extract subject information
        $subject = [];
        if (isset($certDetails['subject']) && is_array($certDetails['subject'])) {
            $subject = $certDetails['subject'];
        }

        // Extract issuer information
        $issuer = [];
        if (isset($certDetails['issuer']) && is_array($certDetails['issuer'])) {
            $issuer = $certDetails['issuer'];
        }

        // Extract validity dates
        $validity = [
            'notBefore' => date('M d H:i:s Y T', $certDetails['validFrom_time_t']),
            'notAfter' => date('M d H:i:s Y T', $certDetails['validTo_time_t']),
        ];

        // Extract serial number (convert to decimal like JavaScript)
        $serialNumber = $certDetails['serialNumber'];
        $serialNumberHex = $certDetails['serialNumberHex'];
        if (ctype_xdigit($serialNumber)) {
            $serialNumberDecimal = (string) hexdec($serialNumber);
        }

        // Extract public key info
        $publicKey = [
            'algorithm' => 'rsaEncryption', // Default for RSA keys
            'n' => null, // Will be populated if needed
            'e' => null,  // Will be populated if needed
        ];

        return [
            'hash' => $certDetails['hash'] ?? '',
            'subject' => $this->formatIssuer($subject),
            'issuer' => $this->formatIssuer($issuer),
            'validity' => $validity,
            'serialNumber' => $serialNumber,
            'serialNumberHex' => $serialNumberHex,
            'serialNumberDecimal' => $serialNumberDecimal,
            'extensions' => $certDetails['extensions'] ?? [],
            'purposes' => $certDetails['purposes'] ?? [],
            'publicKey' => $publicKey,
            'version' => $certDetails['version'] ?? 3,
            'signatureAlgorithm' => $certDetails['signatureTypeSN'] ?? 'sha1WithRSAEncryption',
        ];
    }

    /**
     * Get clean X509 certificate data without metadata for XML signing
     */
    protected function extractCertificateContent(): string
    {
        // Extract only the certificate content between BEGIN and END markers
        $pattern = '/-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----/s';
        if (preg_match($pattern, $this->certificatePem, $matches)) {
            // Remove any whitespace and newlines from the base64 content
            return preg_replace('/\s+/', '', $matches[1]);
        }

        throw new CertificateException('Could not extract clean X509 certificate data');
    }

    /**
     * Extracts modulus and exponent from a private key PEM
     */
    protected function extractPrivateKeyData(): array
    {
        // Get private key resource
        $privateKeyResource = openssl_pkey_get_private($this->privateKeyPem);
        if ($privateKeyResource === false) {
            throw new CertificateException('Unable to parse private key');
        }

        // Get private key details
        $privateKeyDetails = openssl_pkey_get_details($privateKeyResource);
        if ($privateKeyDetails === false || ! isset($privateKeyDetails['rsa'])) {
            throw new CertificateException('Unable to extract RSA key details');
        }

        // Extract modulus (n) and exponent (e) - return raw binary values
        $modulus = $privateKeyDetails['rsa']['n'];
        $exponent = $privateKeyDetails['rsa']['e'];

        return [
            'modulus' => $modulus,
            'exponent' => $exponent,
        ];
    }

    /**
     * Extract the private key and certificate from PKCS#12 raw data.
     *
     * This function accepts PKCS#12 data as raw binary or a Base64-encoded string,
     * decodes it if needed, and uses OpenSSL CLI commands to read the certificate and private key.
     */
    protected function extractPrivateKeyAndCertificateFromPkcs12(string $pkcs12RawData): array
    {
        // Convert input to raw binary if it is Base64
        $pkcs12Binary = $this->isLikelyBase64($pkcs12RawData)
            ? base64_decode($pkcs12RawData, true)
            : $pkcs12RawData;

        if ($pkcs12Binary === false || $pkcs12Binary === '') {
            throw new UnsupportedPkcs12Exception('Invalid PKCS#12 data');
        }

        // Create temporary file for PKCS#12 data
        $tempFile = tempnam(sys_get_temp_dir(), 'pkcs12_');
        if (! $tempFile) {
            throw new UnsupportedPkcs12Exception('Could not create temporary file');
        }

        try {
            // Write PKCS#12 data to temporary file
            if (file_put_contents($tempFile, $pkcs12Binary) === false) {
                throw new UnsupportedPkcs12Exception('Could not write PKCS#12 data to temporary file');
            }

            // Get all certificates and private keys
            $certificates = $this->getAllCertificatesFromPkcs12($tempFile);
            $privateKeys = $this->getAllPrivateKeysFromPkcs12($tempFile);

            //
            if (empty($certificates) || empty($privateKeys)) {
                throw new UnsupportedPkcs12Exception('Could not find certificates or private keys in PKCS#12 data');
            }

            // Get the first certificate
            $certificate = $certificates[0]['certificate'];

            // Determine which private key to use
            $privateKey = $privateKeys[0]['privateKey'];
            if (! $privateKey) {
                throw new UnsupportedPkcs12Exception('Could not find appropriate private key');
            }

            // Set Private key
            $this->privateKeyPem = $privateKey;
            $this->privateKeyData = $this->extractPrivateKeyData();

            // Set certificate
            $this->certificatePem = $certificate;
            $this->certificateContent = $this->extractCertificateContent();
            $this->certificateObject = $this->extractCertificateObject();

            return [
                'privateKey' => $this->privateKeyPem,
                'privateKeyData' => $this->privateKeyData,
                'certificate' => $this->certificatePem,
                'certificateContent' => $this->certificateContent,
                'certificateObject' => $this->certificateObject,
            ];
        } finally {
            // Clean up temporary file
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    /**
     * Checks if a string is likely Base64 encoded
     */
    protected function isLikelyBase64(string $data): bool
    {
        // Remove whitespace and check if it matches Base64 pattern
        $cleanData = preg_replace('/\s/', '', $data);

        return preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $cleanData) && (strlen($cleanData) % 4 === 0);
    }

    /**
     * Executes OpenSSL command and returns output
     */
    protected function executeOpenSslCommand(string $command): string
    {
        $output = [];
        $returnCode = 0;

        exec($command.' 2>&1', $output, $returnCode);

        if ($returnCode !== 0) {
            throw new UnsupportedPkcs12Exception('OpenSSL command failed: '.implode("\n", $output));
        }

        return implode("\n", $output);
    }
}
