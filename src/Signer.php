<?php

namespace DazzaDev\DgtCrSigner;

use DateTime;
use DateTimeZone;
use DazzaDev\DgtCrSigner\Exceptions\CertificateException;
use DazzaDev\DgtCrSigner\Exceptions\SignerException;
use DOMDocument;
use DOMElement;
use Ramsey\Uuid\Uuid;

class Signer
{
    /**
     * XML string
     */
    private string $xmlString = '';

    /**
     * DOMDocument
     */
    private DOMDocument $domDocument;

    /**
     * Version
     */
    private string $version = '1.0';

    /**
     * Encoding
     */
    private string $encoding = 'UTF-8';

    /**
     * Random numbers
     */
    private array $randomNumbers = [];

    /**
     * Hash of comprobante element
     */
    private string $hashComprobante = '';

    /**
     * Hash of signed properties element
     */
    private string $hashSignedProperties = '';

    /**
     * Namespace declarations for canonicalization
     */
    private array $ns = [
        'xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
        'xmlns:xades' => 'http://uri.etsi.org/01903/v1.3.2#',
    ];

    /**
     * Signing time
     */
    private string $signingTime = '';

    /**
     * Signed XML string
     */
    private string $xmlSigned = '';

    /**
     * Signature element
     */
    private ?DOMElement $signatureElement = null;

    /**
     * Key info element
     */
    private ?DOMElement $keyInfoElement = null;

    /**
     * Signed properties element
     */
    private ?DOMElement $signedPropertiesElement = null;

    /**
     * Signed info element
     */
    private ?DOMElement $signedInfoElement = null;

    /**
     * Signature value element
     */
    private ?DOMElement $signatureValueElement = null;

    /**
     * Object element
     */
    private ?DOMElement $objectElement = null;

    /**
     * Certificate
     */
    protected Certificate $certificate;

    /**
     * Constructor
     */
    public function __construct(string $certificatePath, string $certificatePassword)
    {
        $this->certificate = new Certificate($certificatePath, $certificatePassword);
    }

    /**
     * Load XML into DOMDocument
     */
    public function loadXML(DOMDocument|string $xml): Signer
    {
        if ($xml instanceof DOMDocument) {
            $this->xmlString = $xml->saveXML();
        } elseif (is_string($xml)) {
            $this->xmlString = $xml;
        } else {
            throw new SignerException('Invalid XML input.');
        }

        $this->domDocument = new DOMDocument($this->version, $this->encoding);
        $this->domDocument->loadXML($this->xmlString);

        return $this;
    }

    /**
     * Sign the XML document with XAdES-BES format
     */
    public function sign(): string
    {
        // Get hash of comprobante element BEFORE generating dynamic elements
        $this->hashComprobante = $this->getHashComprobante();

        // Set signing time
        $this->signingTime = $this->getSigningTime();

        // Generate the 8 random numbers required for XAdES structure
        $this->generateRandomNumbers();

        // Create signature structure and add it to the document temporarily
        $this->createSignatureStructure();

        $this->domDocument->documentElement->appendChild($this->signatureElement);

        // Get the formatted XML with proper indentation but remove signature indentation
        $this->xmlSigned = $this->domDocument->saveXML();

        return $this->xmlSigned;
    }

    /**
     * Create the complete signature structure
     */
    private function createSignatureStructure(): DOMElement
    {
        $this->signatureElement = $this->domDocument->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Signature');
        $this->signatureElement->setAttribute('Id', 'Signature-'.$this->randomNumbers['signature']);
        $this->signatureElement->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');

        // Create KeyInfo
        $this->createKeyInfo();

        // Create SignedProperties using the separate method
        $this->createSignedProperties();

        // Create SignedInfo
        $this->createSignedInfo();

        // Create SignatureValue
        $this->createSignatureValue();

        // Create Object with XAdES properties
        $this->createObject();

        // Insert SignatureValue before KeyInfo
        $this->signatureElement->appendChild($this->signedInfoElement);
        $this->signatureElement->appendChild($this->signatureValueElement);
        $this->signatureElement->appendChild($this->keyInfoElement);
        $this->signatureElement->appendChild($this->objectElement);

        return $this->signatureElement;
    }

    /**
     * Create the Object element with XAdES properties
     */
    private function createObject(): DOMElement
    {
        $this->objectElement = $this->domDocument->createElement('ds:Object');
        $this->objectElement->setAttribute('Id', 'SignatureObject-'.$this->randomNumbers['object']);

        $qualifyingProperties = $this->domDocument->createElement('xades:QualifyingProperties');
        $qualifyingProperties->setAttribute('xmlns:xades', 'http://uri.etsi.org/01903/v1.3.2#');
        $qualifyingProperties->setAttribute('Target', '#Signature-'.$this->randomNumbers['signature']);

        $qualifyingProperties->appendChild($this->signedPropertiesElement);
        $this->objectElement->appendChild($qualifyingProperties);

        return $this->objectElement;
    }

    /**
     * Create the KeyInfo element
     */
    private function createKeyInfo(): DOMElement
    {
        $this->keyInfoElement = $this->domDocument->createElement('ds:KeyInfo');
        $this->keyInfoElement->setAttribute('Id', 'Certificate-'.$this->randomNumbers['certificate']);

        // X509Data
        $x509Data = $this->domDocument->createElement('ds:X509Data');
        $x509Certificate = $this->domDocument->createElement('ds:X509Certificate');

        // Get certificate content
        $x509Certificate->nodeValue = $this->certificate->getCertificateContent();
        $x509Data->appendChild($x509Certificate);
        $this->keyInfoElement->appendChild($x509Data);

        return $this->keyInfoElement;
    }

    /**
     * Create XAdES SignedProperties element with all its child elements
     */
    private function createSignedProperties(): DOMElement
    {
        $this->signedPropertiesElement = $this->domDocument->createElement('xades:SignedProperties');
        $this->signedPropertiesElement->setAttribute('Id', 'signedProperties-'.$this->randomNumbers['signedProperties']);

        // SignedSignatureProperties
        $signedSignatureProperties = $this->domDocument->createElement('xades:SignedSignatureProperties');

        // SigningTime
        $signingTime = $this->domDocument->createElement('xades:SigningTime');
        $signingTime->nodeValue = $this->signingTime;
        $signedSignatureProperties->appendChild($signingTime);

        // SigningCertificate
        $signingCertificate = $this->domDocument->createElement('xades:SigningCertificate');
        $cert = $this->domDocument->createElement('xades:Cert');

        $certDigest = $this->domDocument->createElement('xades:CertDigest');
        $digestMethod = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $certDigest->appendChild($digestMethod);

        // Add DigestValue for certificate digest
        $digestValue = $this->domDocument->createElement('ds:DigestValue');

        // Calculate SHA256 hash of certificate in DER format
        $certificateDecoded = base64_decode($this->certificate->getCertificateContent(), true);
        $digestValue->nodeValue = $this->sha256Base64($certificateDecoded);
        $certDigest->appendChild($digestValue);
        $cert->appendChild($certDigest);

        $issuerSerial = $this->domDocument->createElement('xades:IssuerSerial');

        // Add X509IssuerName for certificate issuer name
        $x509IssuerName = $this->domDocument->createElement('ds:X509IssuerName');
        $x509IssuerName->nodeValue = $this->certificate->getIssuerName();
        $issuerSerial->appendChild($x509IssuerName);

        // Add X509SerialNumber for certificate serial number
        $x509SerialNumber = $this->domDocument->createElement('ds:X509SerialNumber');
        $x509SerialNumber->nodeValue = $this->certificate->getSerialNumber();
        $issuerSerial->appendChild($x509SerialNumber);

        $cert->appendChild($issuerSerial);
        $signingCertificate->appendChild($cert);
        $signedSignatureProperties->appendChild($signingCertificate);

        // xades:SignaturePolicyIdentifier
        $signaturePolicyIdentifier = $this->domDocument->createElement('xades:SignaturePolicyIdentifier');
        $signaturePolicyId = $this->domDocument->createElement('xades:SignaturePolicyId');
        $sigPolicyId = $this->domDocument->createElement('xades:SigPolicyId');
        $identifier = $this->domDocument->createElement('xades:Identifier');
        $identifier->nodeValue = 'https://cdn.comprobanteselectronicos.go.cr/xmlschemas/Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf';
        $sigPolicyId->appendChild($identifier);

        // PolicyHash
        $sigPolicyHash = $this->domDocument->createElement('xades:SigPolicyHash');
        $sigPolicyDigestMethod = $this->domDocument->createElement('ds:DigestMethod');
        $sigPolicyDigestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $sigPolicyHash->appendChild($sigPolicyDigestMethod);

        $sigPolicyDigestValue = $this->domDocument->createElement('ds:DigestValue');
        $sigPolicyDigestValue->nodeValue = 'DWxin1xWOeI8OuWQXazh4VjLWAaCLAA954em7DMh0h8=';
        $sigPolicyHash->appendChild($sigPolicyDigestValue);

        $signaturePolicyId->appendChild($sigPolicyId);
        $signaturePolicyId->appendChild($sigPolicyHash);
        $signaturePolicyIdentifier->appendChild($signaturePolicyId);
        $signedSignatureProperties->appendChild($signaturePolicyIdentifier);

        $this->signedPropertiesElement->appendChild($signedSignatureProperties);

        // SignedDataObjectProperties
        $signedDataObjectProperties = $this->domDocument->createElement('xades:SignedDataObjectProperties');
        $dataObjectFormat = $this->domDocument->createElement('xades:DataObjectFormat');
        $dataObjectFormat->setAttribute('ObjectReference', '#DocumentRef-'.$this->randomNumbers['referenceId']);

        $mimeType = $this->domDocument->createElement('xades:MimeType');
        $mimeType->nodeValue = 'application/octet-stream';
        $dataObjectFormat->appendChild($mimeType);

        $signedDataObjectProperties->appendChild($dataObjectFormat);
        $this->signedPropertiesElement->appendChild($signedDataObjectProperties);

        // Canonicalize SignedProperties and generate its hash
        $canonicalizedSignedProperties = $this->canonicalizeElement($this->signedPropertiesElement, 'xades:SignedProperties');
        $this->hashSignedProperties = $this->sha256Base64($canonicalizedSignedProperties);

        return $this->signedPropertiesElement;
    }

    /**
     * Create the SignedInfo element
     */
    private function createSignedInfo(): DOMElement
    {
        $this->signedInfoElement = $this->domDocument->createElement('ds:SignedInfo');

        // CanonicalizationMethod
        $canonicalizationMethod = $this->domDocument->createElement('ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $this->signedInfoElement->appendChild($canonicalizationMethod);

        // SignatureMethod
        $signatureMethod = $this->domDocument->createElement('ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        $this->signedInfoElement->appendChild($signatureMethod);

        // Reference to comprobante (root element)
        $referenceInvoice = $this->domDocument->createElement('ds:Reference');
        $referenceInvoice->setAttribute('Id', 'DocumentRef-'.$this->randomNumbers['referenceId']);
        $referenceInvoice->setAttribute('URI', '');

        // Add transforms
        $transformsInvoice = $this->domDocument->createElement('ds:Transforms');

        // Add transform 1
        $transformInvoice = $this->domDocument->createElement('ds:Transform');
        $transformInvoice->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
        $xpathInvoice = $this->domDocument->createElement('ds:XPath');
        $xpathInvoice->nodeValue = 'not(ancestor-or-self::ds:Signature)';
        $transformInvoice->appendChild($xpathInvoice);
        $transformsInvoice->appendChild($transformInvoice);

        // Add transform 2
        $transformInvoice2 = $this->domDocument->createElement('ds:Transform');
        $transformInvoice2->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transformsInvoice->appendChild($transformInvoice2);

        // Add transformsInvoice to referenceInvoice
        $referenceInvoice->appendChild($transformsInvoice);

        // DigestMethod
        $digestMethodInvoice = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethodInvoice->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $referenceInvoice->appendChild($digestMethodInvoice);

        $digestValueInvoice = $this->domDocument->createElement('ds:DigestValue');
        $digestValueInvoice->nodeValue = $this->hashComprobante;
        $referenceInvoice->appendChild($digestValueInvoice);

        // Add ReferenceInvoice to SignedInfo
        $this->signedInfoElement->appendChild($referenceInvoice);

        // Reference to SignedProperties
        $referenceSignedProperties = $this->domDocument->createElement('ds:Reference');
        $referenceSignedProperties->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        $referenceSignedProperties->setAttribute('URI', '#signedProperties-'.$this->randomNumbers['signedProperties']);

        // Add transforms
        $transformsSignedProperties = $this->domDocument->createElement('ds:Transforms');
        $transformSignedProperties = $this->domDocument->createElement('ds:Transform');
        $transformSignedProperties->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        $transformsSignedProperties->appendChild($transformSignedProperties);

        // Add transformsSignedProperties to referenceSignedProperties
        $referenceSignedProperties->appendChild($transformsSignedProperties);

        // Add DigestMethod
        $digestMethodSignedProperties = $this->domDocument->createElement('ds:DigestMethod');
        $digestMethodSignedProperties->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $referenceSignedProperties->appendChild($digestMethodSignedProperties);

        $digestValueSignedProperties = $this->domDocument->createElement('ds:DigestValue');
        $digestValueSignedProperties->nodeValue = $this->hashSignedProperties;
        $referenceSignedProperties->appendChild($digestValueSignedProperties);

        // Add ReferenceSignedProperties to SignedInfo
        $this->signedInfoElement->appendChild($referenceSignedProperties);

        return $this->signedInfoElement;
    }

    /**
     * Create the SignatureValue element
     */
    private function createSignatureValue(): DOMElement
    {
        $this->signatureValueElement = $this->domDocument->createElement('ds:SignatureValue');
        $this->signatureValueElement->setAttribute('Id', 'SignatureValue-'.$this->randomNumbers['signatureValue']);

        // Canonicalize SignedInfo
        $canonicalized = $this->canonicalizeElement($this->signedInfoElement, 'ds:SignedInfo', ['xmlns:ds']);

        $privateKey = openssl_pkey_get_private($this->certificate->getPrivateKeyPem());
        if (! $privateKey) {
            throw new CertificateException('Failed to load private key');
        }

        $signature = '';
        if (! openssl_sign($canonicalized, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new CertificateException('Failed to create digital signature');
        }

        $this->signatureValueElement->nodeValue = base64_encode($signature);

        return $this->signatureValueElement;
    }

    /**
     * Get hash of comprobante element
     */
    private function getHashComprobante(): string
    {
        $canonicalized = $this->domDocument->C14N(true);

        return $this->sha256Base64($canonicalized);
    }

    /**
     * Canonicalize an element with proper namespaces
     */
    private function canonicalizeElement(DOMElement $element, string $tagName, array $namespaces = []): string
    {
        $elementXml = $this->domDocument->saveXML($element);

        $xmlWithNamespaces = $elementXml;
        $nsString = $this->getNamespaces($elementXml, $namespaces);
        if (strpos($xmlWithNamespaces, "<{$tagName} ") !== false) {
            $xmlWithNamespaces = str_replace("<{$tagName} ", "<{$tagName} {$nsString} ", $xmlWithNamespaces);
        } else {
            $xmlWithNamespaces = str_replace("<{$tagName}>", "<{$tagName} {$nsString}>", $xmlWithNamespaces);
        }

        $tempDoc = new DOMDocument($this->version, $this->encoding);
        $tempDoc->loadXML($xmlWithNamespaces);

        return $tempDoc->C14N(true);
    }

    /**
     * Build list of namespaces to ensure on the target element
     */
    private function getNamespaces(string $elementXml, array $namespaces = []): string
    {
        $selectedNamespaces = empty($namespaces) ? $this->ns : array_intersect_key($this->ns, array_flip($namespaces));
        $toAdd = [];
        foreach ($selectedNamespaces as $attr => $value) {
            if (strpos($elementXml, $attr.'=') === false) {
                $toAdd[$attr] = $value;
            }
        }

        return $this->joinArray($toAdd);
    }

    /**
     * Join array elements into namespace declarations string
     */
    private function joinArray(array $array, bool $formatNS = true, string $join = ' '): string
    {
        return implode($join, array_map(function ($value, $key) use ($formatNS) {
            return ($formatNS) ? "{$key}=\"$value\"" : "{$key}=$value";
        }, $array, array_keys($array)));
    }

    /**
     * Calculate SHA256 hash and encode to base64
     */
    private function sha256Base64(string $text): string
    {
        return base64_encode(hash('sha256', $text, true));
    }

    /**
     * Generate the 8 random numbers required for XAdES structure
     */
    private function generateRandomNumbers(): void
    {
        $this->randomNumbers = [
            'certificate' => $this->generateUUID(),
            'signature' => $this->generateUUID(),
            'signedProperties' => $this->generateUUID(),
            'signedInfo' => $this->generateUUID(),
            'referenceId' => $this->generateUUID(),
            'signatureValue' => $this->generateUUID(),
            'object' => $this->generateUUID(),
        ];
    }

    /**
     * Get signing time in ISO 8601 format with time zone offset
     */
    private function getSigningTime(): string
    {
        $now = new DateTime('now', new DateTimeZone('America/Costa_Rica'));

        return $now->format('Y-m-d\TH:i:sP');
    }

    /**
     * Generate a UUIDv4
     */
    private function generateUUID(): string
    {
        $uuid = Uuid::uuid4();

        return $uuid->toString();
    }
}
