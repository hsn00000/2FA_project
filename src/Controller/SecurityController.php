<?php

namespace App\Controller;

use App\Form\Enable2faType;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
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
    public function enable2fa(GoogleAuthenticatorInterface $googleAuthenticator, EntityManagerInterface $entityManager, Request $request): Response
    {
        $myForm = $this->createForm(Enable2faType::class);
        $myForm->handleRequest($request);

        if ($myForm->isSubmitted() && $myForm->isValid()) {
            $data = $myForm->getData();
            $user = $this->getUser();

            // Vérifie le code saisi par l'utilisateur
            if ($googleAuthenticator->checkCode($user, $data['secret'])) {
                $this->addFlash('success', 'L\'authentification à deux facteurs a été activée avec succès.');
                return $this->redirectToRoute('app_logout');
            } else {
                $this->addFlash('error', 'Le code de vérification est invalide. Veuillez réessayer.');
            }
        }

        $user = $this->getUser();
        $secret = $googleAuthenticator->generateSecret();

        // Enregistre le secret dans l'entité User
        $user->setGoogleAuthenticatorSecret($secret);
        $entityManager->persist($user);
        $entityManager->flush();

        //Génère le QR code
        $qrCodeContent = $googleAuthenticator->getQRContent($user);




        return $this->render('enable2fa.html.twig', [
            'secret' => $secret,
            'myForm' => $myForm,
            'qrCodeContent' => $qrCodeContent,
        ]);
    }

}
