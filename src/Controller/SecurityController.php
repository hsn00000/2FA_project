<?php

namespace App\Controller;

use App\Form\Enable2faType;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;


class SecurityController extends AbstractController
{
    #[Route(path: '/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
    #[Route(path: '/enable2fa', name: 'app_enable_2fa')]
    #[IsGranted('ROLE_USER')] // Assurez-vous que l'utilisateur est connecté
    public function enable2fa(GoogleAuthenticatorInterface $googleAuthenticator, EntityManagerInterface $entityManager, Request $request, SessionInterface $session): Response
    {
        // Récupère l'utilisateur actuellement connecté
        $user = $this->getUser();

        $secret = $session->get('2fa_secret');
        if (!$secret) {
            // Génère un nouveau secret et le stocke dans la session
            $secret = $googleAuthenticator->generateSecret();
            $session->set('2fa_secret', $secret);
        }
        // Assigne le secret à l'utilisateur
        $user->setGoogleAuthenticatorSecret($secret);
        // Crée et gère le formulaire
        $myForm = $this->createForm(Enable2faType::class);
        $myForm->handleRequest($request);

        if ($myForm->isSubmitted() && $myForm->isValid()) {
            $data = $myForm->getData();

            // Vérifie le code saisi par l'utilisateur
            if ($googleAuthenticator->checkCode($user, $data['secret'])) {
                $this->addFlash('success', 'L\'authentification à deux facteurs a été activée avec succès.');
                $entityManager->persist($user);
                $entityManager->flush();
                return $this->redirectToRoute('app_login');
            } else {
                $this->addFlash('error', 'Le code de vérification est invalide. Veuillez réessayer.');
            }
        }

        //Génère le QR code
        $qrCodeContent = $googleAuthenticator->getQRContent($user);

        return $this->render('enable2fa.html.twig', [
            'secret' => $secret,
            'myForm' => $myForm,
            'qrCodeContent' => $qrCodeContent,
        ]);
    }

}
