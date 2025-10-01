<?php

namespace App\Controller;

use Sensiolabs\GotenbergBundle\GotenbergPdfInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class PdfController extends AbstractController
{
    #[Route('/pdf', name: 'app_pdf')]
    public function PDF(GotenbergPdfInterface $gotenberg): Response
    {
        return $gotenberg->html()
            ->content('pdf/index.html.twig', [
                'controller_name' => 'PdfController',
            ])
            ->generate()
            ->stream() // will return directly a stream response
            ;
    }
}
