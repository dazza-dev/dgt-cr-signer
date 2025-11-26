<?php

namespace DazzaDev\DgtCrSigner\Exceptions;

class UnsupportedPkcs12Exception extends \Exception
{
    public function __construct(string $message = 'Unsupported PKCS#12 operation', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
