<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final class AfficherDetailUtiisateurController extends AbstractController
{
    #[Route('/afficherdetailutiisateur', name: 'app_afficher_detail_utiisateur')]
    #[isGranted('ROLE_USER')] // Assurez-vous que l'utilisateur est connecté
    public function index(EntityManagerInterface $entityManager): Response
    {
        $user = $this->getUser(); // Récupère l'utilisateur actuellement connecté
        $user = $entityManager->getRepository(User::class)->findOneBy(['id' => $user->getId()]);

        return  $this->render('afficher_detail_utiisateur/index.html.twig', [
            'user' => $user
        ]);
    }
}
