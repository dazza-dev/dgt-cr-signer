# DGT Signer 🇨🇷

Paquete para firmar XML de documentos electrónicos (Factura, Nota crédito, Nota débito y Tiquete Electrónico) basado en las especificaciones de la Dirección General de Tributación (DGT) de Costa Rica.

## Instalación

```bash
composer require dazza-dev/dgt-cr-signer
```

## Guía de uso

```php
use DazzaDev\DgtCrSigner\Signer;

// Instanciar el signer
$signer = new Signer(
    certificatePath: __DIR__ . '/certificado.p12',
    certificatePassword: 'clave_certificado',
);

// XML como string o DOMDocument
$xmlString = file_get_contents(__DIR__ . '/factura.xml');

// Cargar el XML en el signer
$signer->loadXML($xmlString);

// Firmar el XML
$signedXML = $signer->sign();
```

## Envío de XML firmado

Una vez firmado el XML, puedes enviarlo al DGT usando el paquete [DGT Sender](https://github.com/dazza-dev/dgt-cr-sender).

## Generar XML

Si necesitas generar un XML para firmar, puedes usar el paquete [DGT XML Generator](https://github.com/dazza-dev/dgt-xml-generator).

## Contribuciones

Contribuciones son bienvenidas. Si encuentras algún error o tienes ideas para mejoras, por favor abre un issue o envía un pull request. Asegúrate de seguir las guías de contribución.

## Autor

DGT Signer fue creado por [DAZZA](https://github.com/dazza-dev).

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](https://opensource.org/licenses/MIT).
