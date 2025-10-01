<?php
namespace App\Service;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Component\HttpFoundation\File\File;

class GotenbergService
{
    private string $apiUrl;
    private HttpClientInterface $httpClient;

    public function __construct(
        HttpClientInterface $httpClient,
        string $gotenbergApiUrl
    ) {
        $this->httpClient = $httpClient;
        $this->apiUrl = rtrim($gotenbergApiUrl, '/');
    }

    /**
     * Convertir une URL en PDF
     */
    public function convertUrlToPdf(string $url): string
    {
        $response = $this->httpClient->request('POST', $this->apiUrl . '/forms/chromium/convert/url', [
            'body' => [
                'url' => $url,
            ],
        ]);

        return $response->getContent();
    }

    /**
     * Convertir du HTML en PDF
     */
    public function convertHtmlToPdf(string $html, array $options = []): string
    {
        $body = [
            'files' => [
                'index.html' => $html,
            ],
        ];

        // Options supplémentaires (marges, format, etc.)
        if (isset($options['marginTop'])) {
            $body['marginTop'] = $options['marginTop'];
        }
        if (isset($options['marginBottom'])) {
            $body['marginBottom'] = $options['marginBottom'];
        }
        if (isset($options['paperWidth'])) {
            $body['paperWidth'] = $options['paperWidth'];
        }
        if (isset($options['paperHeight'])) {
            $body['paperHeight'] = $options['paperHeight'];
        }

        $response = $this->httpClient->request('POST', $this->apiUrl . '/forms/chromium/convert/html', [
            'body' => $body,
        ]);

        return $response->getContent();
    }

    /**
     * Convertir un template Twig en PDF
     */
    public function convertTwigToPdf(string $renderedTemplate, array $options = []): string
    {
        return $this->convertHtmlToPdf($renderedTemplate, $options);
    }

    /**
     * Convertir un fichier Office (Word, Excel, etc.) en PDF
     */
    public function convertOfficeToPdf(File $file): string
    {
        $response = $this->httpClient->request('POST', $this->apiUrl . '/forms/libreoffice/convert', [
            'body' => [
                'files' => fopen($file->getPathname(), 'r'),
            ],
        ]);

        return $response->getContent();
    }
}


