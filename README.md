# 🔐 Guide Complet - Sécurité Symfony
## Authentification à deux facteurs (2FA) + Réinitialisation de mot de passe

---

## 📋 Table des matières

1. [Installation du projet Symfony](#-1-installation-du-projet-symfony)
2. [Configuration de l'authentification 2FA](#-2-authentification-à-deux-facteurs-2fa)
3. [Configuration de la réinitialisation de mot de passe](#-3-réinitialisation-de-mot-de-passe)
4. [Explications détaillées du code](#-4-explications-détaillées-du-code)
5. [Bonnes pratiques de sécurité](#-5-bonnes-pratiques-de-sécurité)
6. [Troubleshooting](#-6-troubleshooting)

---

## ⚙️ 1. Installation du projet Symfony

### Étapes d'initialisation

```bash
# Cloner le projet
git clone <url-du-repo>
cd <nom-du-projet>

# Installer les dépendances
composer install

# Configuration de l'environnement
cp .env .env.local

# Créer et configurer la base de données
symfony console doctrine:database:create
symfony console doctrine:migrations:migrate

# Démarrer le serveur
symfony server:start -d

# Créer un utilisateur de test
symfony console app:add-user user@example.com motdepasse --role ROLE_ADMIN
```

---

## 🔐 2. Authentification à deux facteurs (2FA)

### 2.1 Installation des bundles 2FA

```bash
# Bundles essentiels
composer require scheb/2fa-bundle scheb/2fa-google-authenticator

# Bundles optionnels (recommandés)
composer require scheb/2fa-backup-code      # Codes de secours
composer require scheb/2fa-trusted-device   # Appareils de confiance
```

### 2.2 Configuration des routes

**Fichier :** `config/routes/scheb_2fa.yaml`

```yaml
# Route pour afficher le formulaire 2FA
2fa_login:
    path: /2fa
    controller: "scheb_two_factor.form_controller::form"

# Route pour vérifier le code 2FA
2fa_login_check:
    path: /2fa_check
```

### 2.3 Configuration de la sécurité

**Fichier :** `config/packages/security.yaml`

```yaml
security:
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        main:
            provider: app_user_provider
            custom_authenticator: App\Security\LoginFormAuthenticator
            logout:
                path: app_logout
            # Configuration 2FA
            two_factor:
                auth_form_path: 2fa_login      # Où rediriger pour la 2FA
                check_path: 2fa_login_check    # Où vérifier le code
```

### 2.4 Configuration du bundle 2FA

**Fichier :** `config/packages/scheb_two_factor.yaml`

```yaml
scheb_two_factor:
    # Types de tokens de sécurité acceptés
    security_tokens:
        - Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken

    # Configuration Google Authenticator
    google:
        enabled: true
        server_name: "MonProjetSymfony"  # Nom affiché dans l'app
        issuer: "MonProjet"              # Émetteur du token
        digits: 6                        # Nombre de chiffres du code
        window: 1                        # Fenêtre de tolérance temporelle

    # Fonctionnalités optionnelles
    backup_codes:
        enabled: true
        codes: 10                        # Nombre de codes de secours
        length: 6                        # Longueur des codes
    
    trusted_device:
        enabled: true
        lifetime: 2592000                # 30 jours en secondes
```

### 2.5 Mise à jour de l'entité User

```php
<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Scheb\TwoFactorBundle\Model\Google\TwoFactorInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

#[ORM\Entity]
class User implements UserInterface, PasswordAuthenticatedUserInterface, TwoFactorInterface
{
    // ... autres propriétés

    #[ORM\Column(type: 'boolean')]
    private bool $isGoogleAuthenticatorEnabled = false;

    #[ORM\Column(type: 'string', nullable: true)]
    private ?string $googleAuthenticatorSecret = null;

    // Méthodes requises par TwoFactorInterface
    public function isGoogleAuthenticatorEnabled(): bool
    {
        return $this->isGoogleAuthenticatorEnabled;
    }

    public function getGoogleAuthenticatorSecret(): ?string
    {
        return $this->googleAuthenticatorSecret;
    }

    public function setGoogleAuthenticatorSecret(?string $secret): self
    {
        $this->googleAuthenticatorSecret = $secret;
        return $this;
    }

    public function enableGoogleAuthenticator(): self
    {
        $this->isGoogleAuthenticatorEnabled = true;
        return $this;
    }

    public function disableGoogleAuthenticator(): self
    {
        $this->isGoogleAuthenticatorEnabled = false;
        return $this;
    }
}
```

**Migration de la base :**
```bash
symfony console make:migration
symfony console doctrine:migrations:migrate
```

### 2.6 Commande pour activer la 2FA

**Fichier :** `src/Command/Enable2FACommand.php`

```php
<?php

namespace App\Command;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticatorInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'app:enable-2fa')]
class Enable2FACommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em,
        private GoogleAuthenticatorInterface $googleAuthenticator
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('email', InputArgument::REQUIRED, 'Email de l\'utilisateur');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $email = $input->getArgument('email');
        $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user) {
            $output->writeln("<error>Utilisateur introuvable</error>");
            return Command::FAILURE;
        }

        // Génération du secret et activation
        $secret = $this->googleAuthenticator->generateSecret();
        $user->setGoogleAuthenticatorSecret($secret)->enableGoogleAuthenticator();
        $this->em->flush();

        // Affichage du QR Code
        $qrCodeUrl = $this->googleAuthenticator->getQRContent($user);
        $output->writeln("2FA activée pour $email");
        $output->writeln("Ajoutez ce QR Code à Google Authenticator :");
        $output->writeln($qrCodeUrl);

        return Command::SUCCESS;
    }
}
```

**Utilisation :**
```bash
symfony console app:enable-2fa user@example.com
```

---

## 🔑 3. Réinitialisation de mot de passe

### 3.1 Installation du bundle

```bash
composer require symfonycasts/reset-password-bundle
```

### 3.2 Configuration de base

```bash
# Créer l'entité ResetPasswordRequest
php bin/console make:reset-password

# Créer et exécuter les migrations
php bin/console make:migration
php bin/console doctrine:migrations:migrate
```

### 3.3 Configuration du bundle

**Fichier :** `config/packages/reset_password.yaml`

```yaml
symfonycasts_reset_password:
    request_password_repository: App\Repository\ResetPasswordRequestRepository
    lifetime: 3600                    # Durée de vie : 1 heure
    throttle_limit: 3600              # Limitation : 1 demande par heure
    enable_garbage_collection: true   # Nettoyage automatique des tokens expirés
```

### 3.4 Contrôleur de réinitialisation

```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use SymfonyCasts\Bundle\ResetPassword\ResetPasswordHelperInterface;
use SymfonyCasts\Bundle\ResetPassword\Exception\ResetPasswordExceptionInterface;

class ResetPasswordController extends AbstractController
{
    public function __construct(
        private ResetPasswordHelperInterface $resetPasswordHelper,
        private EntityManagerInterface $entityManager
    ) {}

    #[Route('/reset-password', name: 'app_forgot_password_request')]
    public function request(Request $request, MailerInterface $mailer, UserRepository $userRepository): Response
    {
        if ($request->isMethod('POST')) {
            return $this->processSendingPasswordResetEmail(
                $request->request->get('email'),
                $mailer,
                $userRepository
            );
        }

        return $this->render('reset_password/request.html.twig');
    }

    #[Route('/reset-password/reset/{token}', name: 'app_reset_password')]
    public function reset(Request $request, UserPasswordHasherInterface $passwordHasher, string $token = null): Response
    {
        if ($token) {
            // Stocker le token en session pour éviter de l'exposer dans l'URL
            $this->storeTokenInSession($token);
            return $this->redirectToRoute('app_reset_password');
        }

        $token = $this->getTokenFromSession();
        if (null === $token) {
            throw $this->createNotFoundException('Token de réinitialisation introuvable.');
        }

        try {
            $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
        } catch (ResetPasswordExceptionInterface $e) {
            $this->addFlash('reset_password_error', 'Token invalide ou expiré.');
            return $this->redirectToRoute('app_forgot_password_request');
        }

        // Le token est valide, traiter la soumission du formulaire
        if ($request->isMethod('POST')) {
            $this->removeTokenFromSession();

            $plainPassword = $request->request->get('plainPassword');
            
            // Encoder le nouveau mot de passe
            $encodedPassword = $passwordHasher->hashPassword($user, $plainPassword);
            $user->setPassword($encodedPassword);
            
            // Supprimer la demande de réinitialisation
            $this->resetPasswordHelper->removeResetRequest($token);
            
            $this->entityManager->flush();
            $this->cleanSessionAfterReset();

            return $this->redirectToRoute('app_login');
        }

        return $this->render('reset_password/reset.html.twig', [
            'resetForm' => null, // Vous pouvez créer un formulaire Symfony ici
        ]);
    }

    private function processSendingPasswordResetEmail(string $emailFormData, MailerInterface $mailer, UserRepository $userRepository): Response
    {
        $user = $userRepository->findOneBy(['email' => $emailFormData]);

        // Ne pas révéler si l'utilisateur existe ou non
        if (!$user) {
            return $this->redirectToRoute('app_check_email');
        }

        try {
            $resetToken = $this->resetPasswordHelper->generateResetToken($user);
        } catch (ResetPasswordExceptionInterface $e) {
            return $this->redirectToRoute('app_check_email');
        }

        $email = (new Email())
            ->from('hello@example.com')
            ->to($user->getEmail())
            ->subject('Demande de réinitialisation de mot de passe')
            ->html($this->renderView('reset_password/email.html.twig', [
                'resetToken' => $resetToken,
            ]));

        $mailer->send($email);
        
        return $this->redirectToRoute('app_check_email');
    }
}
```

---

## 💡 4. Explications détaillées du code

### 4.1 Contrôleur d'activation 2FA - Analyse ligne par ligne

```php
#[Route(path: '/enable2fa', name: 'app_enable_2fa')]
#[IsGranted('ROLE_USER')]
public function enable2fa(
    GoogleAuthenticatorInterface $googleAuthenticator, 
    EntityManagerInterface $entityManager, 
    Request $request, 
    SessionInterface $session
): Response
{
```

**Explications :**
- `#[Route(...)]` : Définit l'URL `/enable2fa` accessible via GET/POST
- `#[IsGranted('ROLE_USER')]` : Seuls les utilisateurs connectés peuvent accéder à cette page
- **Injection de dépendances** :
    - `GoogleAuthenticatorInterface` : Service pour gérer Google Authenticator
    - `EntityManagerInterface` : Pour persister les données en base
    - `Request` : Pour récupérer les données du formulaire
    - `SessionInterface` : Pour stocker temporairement le secret

```php
$user = $this->getUser();

$secret = $session->get('2fa_secret');
if (!$secret) {
    $secret = $googleAuthenticator->generateSecret();
    $session->set('2fa_secret', $secret);
}
```

**Explications :**
- `$this->getUser()` : Récupère l'utilisateur connecté
- **Gestion du secret** :
    - Vérifie si un secret existe déjà en session
    - Sinon, génère un nouveau secret cryptographique
    - Le stocke en session (temporaire, pas encore en base)

```php
$user->setGoogleAuthenticatorSecret($secret);

$myForm = $this->createForm(Enable2faType::class);
$myForm->handleRequest($request);
```

**Explications :**
- `setGoogleAuthenticatorSecret()` : Assigne le secret à l'utilisateur (temporaire)
- `createForm()` : Crée le formulaire de validation
- `handleRequest()` : Traite la soumission du formulaire

```php
if ($myForm->isSubmitted() && $myForm->isValid()) {
    $data = $myForm->getData();

    if ($googleAuthenticator->checkCode($user, $data['secret'])) {
        $this->addFlash('success', 'L\'authentification à deux facteurs a été activée avec succès.');
        $entityManager->persist($user);
        $entityManager->flush();
        return $this->redirectToRoute('app_login');
    } else {
        $this->addFlash('error', 'Le code de vérification est invalide. Veuillez réessayer.');
    }
}
```

**Explications :**
- **Validation du code** :
    - `checkCode()` : Vérifie que le code entré correspond au secret
    - Si correct → sauvegarde définitive en base de données
    - Si incorrect → affiche un message d'erreur, le secret reste en session

```php
$qrCodeContent = $googleAuthenticator->getQRContent($user);

return $this->render('enable2fa.html.twig', [
    'secret' => $secret,
    'myForm' => $myForm,
    'qrCodeContent' => $qrCodeContent,
]);
```

**Explications :**
- `getQRContent()` : Génère l'URL du QR code pour Google Authenticator
- La vue reçoit :
    - Le secret (pour affichage manuel)
    - Le formulaire
    - Le contenu du QR code

### 4.2 Workflow complet de la 2FA

```mermaid
graph TD
    A[Utilisateur se connecte] --> B[Email + Mot de passe]
    B --> C{Identifiants valides?}
    C -->|Non| B
    C -->|Oui| D{2FA activée?}
    D -->|Non| E[Connexion réussie]
    D -->|Oui| F[Redirection vers /2fa]
    F --> G[Saisie du code 6 chiffres]
    G --> H{Code valide?}
    H -->|Non| G
    H -->|Oui| E
```

### 4.3 Sécurité du système de reset password

**Protection contre les attaques :**

1. **Timing attacks** : Le bundle utilise des comparaisons sécurisées
2. **Token prediction** : Génération cryptographiquement sûre
3. **Brute force** : Limitation du nombre de demandes par IP/utilisateur
4. **Information disclosure** : Ne révèle jamais si un email existe

**Cycle de vie d'un token :**
```php
// 1. Génération
$resetToken = $this->resetPasswordHelper->generateResetToken($user);

// 2. Validation
$user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);

// 3. Suppression après utilisation
$this->resetPasswordHelper->removeResetRequest($token);
```

---

## 🛡️ 5. Bonnes pratiques de sécurité

### 5.1 Configuration HTTPS obligatoire

```yaml
# config/packages/security.yaml
security:
    access_control:
        - { path: ^/2fa, roles: IS_AUTHENTICATED_FULLY, requires_channel: https }
        - { path: ^/reset-password, requires_channel: https }
```

### 5.2 Validation côté serveur

```php
// Toujours valider les inputs
private function validateEmail(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// Limitation de taux
private function isRateLimited(Request $request): bool
{
    // Implémenter une logique de limitation par IP
    return false;
}
```

### 5.3 Logging de sécurité

```php
use Psr\Log\LoggerInterface;

class SecurityController
{
    public function __construct(private LoggerInterface $securityLogger) {}

    private function logSecurityEvent(string $event, array $context = []): void
    {
        $this->securityLogger->info($event, array_merge([
            'ip' => $this->request->getClientIp(),
            'user_agent' => $this->request->headers->get('User-Agent'),
            'timestamp' => new \DateTime(),
        ], $context));
    }
}
```

---

## 🔧 6. Troubleshooting

### Problèmes courants et solutions

| Problème | Cause probable | Solution |
|----------|----------------|----------|
| QR Code ne s'affiche pas | Secret non généré | Vérifier la session et la génération du secret |
| Code 2FA toujours invalide | Horloge désynchronisée | Ajuster le paramètre `window` dans la config |
| Token de reset expiré trop vite | Configuration `lifetime` trop courte | Augmenter la durée dans `reset_password.yaml` |
| Emails de reset non envoyés | Configuration du mailer | Vérifier `MAILER_DSN` dans `.env` |

### Commandes de maintenance

```bash
# Nettoyer les tokens expirés
php bin/console reset-password:remove-expired

# Vérifier la configuration 2FA
php bin/console debug:config scheb_two_factor

# Tester l'envoi d'emails
php bin/console mailer:test

# Voir les logs de sécurité
tail -f var/log/security.log
```

### Variables d'environnement importantes

```bash
# .env.local
DATABASE_URL="mysql://user:password@127.0.0.1:3306/app_db"
MAILER_DSN="smtp://localhost:1025"
APP_SECRET="your-secret-key-here"
```

---

## 📚 Ressources supplémentaires

- [Documentation SchebTwoFactorBundle](https://symfony.com/bundles/SchebTwoFactorBundle/current/index.html)
- [Documentation Reset Password Bundle](https://symfony.com/bundles/SymfonyCastsResetPasswordBundle/current/index.html)
- [Guide de sécurité Symfony](https://symfony.com/doc/current/security.html)
- [OWASP Authentication Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Authentication_Cheat_Sheet.html)
