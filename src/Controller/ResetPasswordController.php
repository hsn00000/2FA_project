<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\ChangePasswordFormType;
use App\Form\ResetPasswordRequestFormType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\Translation\TranslatorInterface;
use SymfonyCasts\Bundle\ResetPassword\Controller\ResetPasswordControllerTrait;
use SymfonyCasts\Bundle\ResetPassword\Exception\ResetPasswordExceptionInterface;
use SymfonyCasts\Bundle\ResetPassword\ResetPasswordHelperInterface;

#[Route('/reset-password')]
class ResetPasswordController extends AbstractController
{
    use ResetPasswordControllerTrait; // Traite pour gérer les tokens et la session

    // Constructeur : injection des services ResetPasswordHelper et EntityManager
    public function __construct(
        private ResetPasswordHelperInterface $resetPasswordHelper,
        private EntityManagerInterface $entityManager
    ) {
    }

    /**
     * Étape 1 : Affiche et traite le formulaire de demande de réinitialisation.
     */
    #[Route('', name: 'app_forgot_password_request')]
    public function request(Request $request, MailerInterface $mailer, TranslatorInterface $translator): Response
    {
        // Création du formulaire pour demander la réinitialisation du mot de passe
        $form = $this->createForm(ResetPasswordRequestFormType::class);
        $form->handleRequest($request); // Gestion de la soumission

        // Si le formulaire est soumis et valide
        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $email */
            $email = $form->get('email')->getData();

            // Traitement de l'envoi du mail de réinitialisation
            return $this->processSendingPasswordResetEmail($email, $mailer, $translator);
        }

        // Affiche le formulaire
        return $this->render('reset_password/request.html.twig', [
            'requestForm' => $form,
        ]);
    }

    /**
     * Étape 2 : Page de confirmation après la demande.
     */
    #[Route('/check-email', name: 'app_check_email')]
    public function checkEmail(): Response
    {
        // On récupère le token en session
        if (null === ($resetToken = $this->getTokenObjectFromSession())) {
            // Si aucun token, on génère un faux token pour ne pas révéler si l'email existe
            $resetToken = $this->resetPasswordHelper->generateFakeResetToken();
        }

        return $this->render('reset_password/check_email.html.twig', [
            'resetToken' => $resetToken,
        ]);
    }

    /**
     * Étape 3 : Validation et réinitialisation du mot de passe via le lien email.
     */
    #[Route('/reset/{token}', name: 'app_reset_password')]
    public function reset(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        TranslatorInterface $translator,
        ?string $token = null
    ): Response
    {
        if ($token) {
            // Stocke le token en session et le supprime de l'URL pour éviter les fuites
            $this->storeTokenInSession($token);
            return $this->redirectToRoute('app_reset_password');
        }

        // Récupère le token depuis la session
        $token = $this->getTokenFromSession();

        if (null === $token) {
            throw $this->createNotFoundException('No reset password token found in the URL or in the session.');
        }

        try {
            /** @var User $user */
            // Valide le token et récupère l'utilisateur associé
            $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
        } catch (ResetPasswordExceptionInterface $e) {
            // Si le token n'est pas valide, affiche un message d'erreur
            $this->addFlash('reset_password_error', sprintf(
                '%s - %s',
                $translator->trans(ResetPasswordExceptionInterface::MESSAGE_PROBLEM_VALIDATE, [], 'ResetPasswordBundle'),
                $translator->trans($e->getReason(), [], 'ResetPasswordBundle')
            ));

            return $this->redirectToRoute('app_forgot_password_request');
        }

        // Le token est valide, on affiche le formulaire pour choisir un nouveau mot de passe
        $form = $this->createForm(ChangePasswordFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // Supprime le token pour qu'il ne puisse être utilisé qu'une seule fois
            $this->resetPasswordHelper->removeResetRequest($token);

            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            // Hash le mot de passe et le sauvegarde en base
            $user->setPassword($passwordHasher->hashPassword($user, $plainPassword));
            $this->entityManager->flush();

            // Nettoie la session après le changement de mot de passe
            $this->cleanSessionAfterReset();

            return $this->redirectToRoute('app_home');
        }

        // Affiche le formulaire de réinitialisation
        return $this->render('reset_password/reset.html.twig', [
            'resetForm' => $form,
        ]);
    }

    /**
     * Méthode privée : envoi du mail de réinitialisation.
     */
    private function processSendingPasswordResetEmail(
        string $emailFormData,
        MailerInterface $mailer,
        TranslatorInterface $translator
    ): RedirectResponse
    {
        // Recherche l'utilisateur par email
        $user = $this->entityManager->getRepository(User::class)->findOneBy([
            'email' => $emailFormData,
        ]);

        // Si aucun utilisateur trouvé, ne rien révéler et rediriger vers la page de confirmation
        if (!$user) {
            return $this->redirectToRoute('app_check_email');
        }

        try {
            // Génère le token de réinitialisation
            $resetToken = $this->resetPasswordHelper->generateResetToken($user);
        } catch (ResetPasswordExceptionInterface $e) {
            return $this->redirectToRoute('app_check_email');
        }

        // Prépare le mail de réinitialisation
        $email = (new TemplatedEmail())
            ->from(new Address('contact@hsn.com', 'HSN'))
            ->to((string) $user->getEmail())
            ->subject('Your password reset request')
            ->htmlTemplate('reset_password/email.html.twig')
            ->context([
                'resetToken' => $resetToken,
            ]);

        // Envoi du mail
        $mailer->send($email);

        // Stocke le token en session pour l'étape de confirmation
        $this->setTokenObjectInSession($resetToken);

        return $this->redirectToRoute('app_check_email');
    }
}

//request() → formulaire de demande, envoie le mail avec le token.
//checkEmail() → page de confirmation après demande (génère un faux token pour la sécurité).
//reset() → vérifie le token, affiche le formulaire de changement, hash et sauvegarde le nouveau mot de passe.
//processSendingPasswordResetEmail() → envoie le mail et stocke le token en session.
