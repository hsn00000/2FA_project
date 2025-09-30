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

### 3.0 Qu'est-ce que le Reset Password Bundle ?

#### 🎯 **Objectif principal**

Le **Reset Password Bundle** est un composant Symfony qui permet aux utilisateurs qui ont **oublié leur mot de passe** de le réinitialiser de manière **sécurisée** sans intervention d'un administrateur.

#### 🤔 **Pourquoi ce bundle existe-t-il ?**

**Le problème :**
```
❌ Utilisateur : "J'ai oublié mon mot de passe !"
❌ Sans bundle : Développement complexe, risques de failles de sécurité
❌ Stocker le mot de passe en clair : INTERDIT et dangereux
❌ Envoyer le mot de passe par email : IMPOSSIBLE (hashé en base)
```

**La solution :**
```
✅ Génération d'un lien temporaire sécurisé
✅ Envoi par email
✅ L'utilisateur peut définir un nouveau mot de passe
✅ Le tout de manière automatisée et sécurisée
```

#### 🔐 **Comment ça fonctionne ? (Vue d'ensemble)**

```mermaid
graph LR
    A[👤 Utilisateur oublie<br/>son mot de passe] --> B[📝 Demande de<br/>réinitialisation]
    B --> C[🔑 Token unique<br/>généré]
    C --> D[📧 Email envoyé<br/>avec lien]
    D --> E[🔗 Clic sur le lien]
    E --> F[✍️ Saisie nouveau<br/>mot de passe]
    F --> G[✅ Mot de passe<br/>mis à jour]
```
#### 🔑 **Qu'est-ce que un Token ?**
Un Token est une valeur unique générée aléatoirement (souvent cryptographique). Il sert à authentifier ou autoriser une action (connexion, reset password, 2FA…). Il a généralement une durée de vie limitée et est à usage unique (ex. : lien de réinitialisation de mot de passe).


#### 🛡️ **Fonctionnalités de sécurité intégrées**

| Fonctionnalité | Description | Bénéfice |
|----------------|-------------|----------|
| **Token cryptographique** | Génération aléatoire sécurisée | Impossible à deviner ou prédire |
| **Expiration temporelle** | Token valide 1 heure (configurable) | Fenêtre d'attaque limitée |
| **Usage unique** | Token supprimé après utilisation | Impossible de réutiliser le lien |
| **Hachage du token** | Token stocké en version hashée | Même si la DB est compromise, tokens inutilisables |
| **Throttling** | Limitation des demandes | Protection contre le spam |
| **Validation stricte** | Vérifications multiples | Robustesse contre les attaques |

#### 🚫 **Ce que le bundle EMPÊCHE**

**1. Attaque par énumération d'utilisateurs**
```php
// ❌ Mauvaise pratique
if (!$user) {
    return "Cet email n'existe pas";
}

// ✅ Bonne pratique (Bundle)
// Retourne toujours le même message, que l'email existe ou non
return "Si votre email existe, vous recevrez un lien";
```

**2. Attaque par force brute**
```php
// Le bundle limite automatiquement :
// - 1 demande par heure par utilisateur
// - Tokens impossibles à deviner (256 bits d'entropie)
```

**3. Réutilisation de tokens**
```php
// Après changement de mot de passe :
$this->resetPasswordHelper->removeResetRequest($token);
// ✅ Le token est détruit, le lien devient inutile
```

**4. Timing attacks**
```php
// Le bundle utilise hash_equals() pour comparer les tokens
// Temps de comparaison constant, quelle que soit la validité
```

#### 📊 **Comparaison : Avec vs Sans le bundle**

| Aspect | ❌ Sans Bundle | ✅ Avec Bundle |
|--------|----------------|----------------|
| **Développement** | 2-3 jours de code | 30 minutes d'installation |
| **Sécurité** | Risque de failles | Best practices intégrées |
| **Gestion tokens** | À implémenter manuellement | Automatique (génération, validation, nettoyage) |
| **Tests** | À écrire soi-même | Déjà testés par la communauté |
| **Maintenance** | Corrections de bugs à faire | Mises à jour par SymfonyCasts |
| **Base de données** | Conception du schéma | Entité générée automatiquement |

#### 🎭 **Cas d'usage réels**

**Scénario 1 : Utilisateur légitime**
```
1. Jean a oublié son mot de passe
2. Il clique sur "Mot de passe oublié ?"
3. Il reçoit un email dans 30 secondes
4. Il clique sur le lien (valide 1h)
5. Il définit un nouveau mot de passe
6. Il peut se reconnecter immédiatement
```

**Scénario 2 : Tentative d'attaque**
```
1. Un attaquant demande 100 réinitialisations pour user@example.com
2. Le bundle détecte le throttling
3. Seule la 1ère demande génère un email
4. L'attaquant ne peut pas deviner le token (trop long, aléatoire)
5. Même s'il accède à la DB, les tokens sont hashés
6. Après 1h, tous les tokens expirent automatiquement
```

#### 💡 **Pourquoi utiliser CE bundle spécifiquement ?**

**1. Créé par SymfonyCasts**
- Équipe officielle de formation Symfony
- Respect des standards Symfony
- Documentation excellente

**2. Production-ready**
- Utilisé par des milliers d'applications
- Testé en conditions réelles
- Bugs corrigés rapidement

**3. Flexible**
- Configuration simple mais puissante
- S'adapte à vos besoins (durée tokens, throttling, etc.)
- Contrôle total sur l'UI et les emails

**4. Maintenance active**
- Compatible avec les dernières versions de Symfony
- Mises à jour de sécurité régulières
- Communauté active

#### 🔧 **Ce que vous contrôlez toujours**

Le bundle gère la **logique de sécurité**, mais vous gardez le contrôle sur :

```
✅ Le design des formulaires et pages
✅ Le contenu et design des emails
✅ La durée de validité des tokens
✅ Les messages affichés aux utilisateurs
✅ La logique métier supplémentaire (logs, notifications, etc.)
✅ Les redirections après réinitialisation
```

#### 📈 **Architecture du bundle**

```mermaid
graph TD
    A[ResetPasswordController] --> B[ResetPasswordHelper]
    B --> C[ResetPasswordRequest Entity]
    C --> D[(Database)]
    B --> E[Token Generator]
    B --> F[Token Validator]
    A --> G[Mailer Service]
    G --> H[📧 Email Template]
    
    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#f0e1ff
    style D fill:#e1ffe1
```

**Composants principaux :**

| Composant | Rôle | Fichier |
|-----------|------|---------|
| **Controller** | Gère les requêtes HTTP | `src/Controller/ResetPasswordController.php` |
| **Helper** | Logique métier (génération, validation) | Service injecté |
| **Entity** | Stockage des demandes | `src/Entity/ResetPasswordRequest.php` |
| **Repository** | Accès base de données | `src/Repository/ResetPasswordRequestRepository.php` |
| **Mailer** | Envoi des emails | Service Symfony |

---

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

### 3.4 Contrôleur de réinitialisation - Code complet et annoté

```php
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
    // 🔧 Trait fourni par le bundle pour les méthodes de gestion de session
    use ResetPasswordControllerTrait;

    public function __construct(
        private ResetPasswordHelperInterface $resetPasswordHelper,
        private EntityManagerInterface $entityManager
    ) {
    }

    /**
     * 📝 Affiche et traite le formulaire de demande de réinitialisation
     */
    #[Route('', name: 'app_forgot_password_request')]
    public function request(
        Request $request, 
        MailerInterface $mailer, 
        TranslatorInterface $translator
    ): Response
    {
        // Création du formulaire Symfony (type FormType)
        $form = $this->createForm(ResetPasswordRequestFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            /** @var string $email */
            $email = $form->get('email')->getData();

            return $this->processSendingPasswordResetEmail(
                $email, 
                $mailer, 
                $translator
            );
        }

        return $this->render('reset_password/request.html.twig', [
            'requestForm' => $form,
        ]);
    }

    /**
     * ✅ Page de confirmation après demande de réinitialisation
     * (Affichée que l'email existe ou non - sécurité)
     */
    #[Route('/check-email', name: 'app_check_email')]
    public function checkEmail(): Response
    {
        // Génère un faux token si l'utilisateur n'existe pas
        // Empêche de savoir si l'email est enregistré
        if (null === ($resetToken = $this->getTokenObjectFromSession())) {
            $resetToken = $this->resetPasswordHelper->generateFakeResetToken();
        }

        return $this->render('reset_password/check_email.html.twig', [
            'resetToken' => $resetToken,
        ]);
    }

    /**
     * 🔄 Valide et traite l'URL de réinitialisation (lien cliqué dans l'email)
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
            // Stocke le token en session et le retire de l'URL
            // Évite que le token soit exposé à du JavaScript tiers
            $this->storeTokenInSession($token);

            return $this->redirectToRoute('app_reset_password');
        }

        $token = $this->getTokenFromSession();

        if (null === $token) {
            throw $this->createNotFoundException(
                'No reset password token found in the URL or in the session.'
            );
        }

        try {
            /** @var User $user */
            $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
        } catch (ResetPasswordExceptionInterface $e) {
            // Traduction des messages d'erreur
            $this->addFlash('reset_password_error', sprintf(
                '%s - %s',
                $translator->trans(
                    ResetPasswordExceptionInterface::MESSAGE_PROBLEM_VALIDATE, 
                    [], 
                    'ResetPasswordBundle'
                ),
                $translator->trans($e->getReason(), [], 'ResetPasswordBundle')
            ));

            return $this->redirectToRoute('app_forgot_password_request');
        }

        // Le token est valide, permettre le changement de mot de passe
        $form = $this->createForm(ChangePasswordFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // ⚠️ Token à usage unique : le supprimer
            $this->resetPasswordHelper->removeResetRequest($token);

            /** @var string $plainPassword */
            $plainPassword = $form->get('plainPassword')->getData();

            // Hasher le nouveau mot de passe
            $user->setPassword(
                $passwordHasher->hashPassword($user, $plainPassword)
            );
            $this->entityManager->flush();

            // Nettoyage de la session après changement
            $this->cleanSessionAfterReset();

            return $this->redirectToRoute('app_home');
        }

        return $this->render('reset_password/reset.html.twig', [
            'resetForm' => $form,
        ]);
    }

    /**
     * 📧 Traite l'envoi de l'email de réinitialisation
     */
    private function processSendingPasswordResetEmail(
        string $emailFormData, 
        MailerInterface $mailer, 
        TranslatorInterface $translator
    ): RedirectResponse
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy([
            'email' => $emailFormData,
        ]);

        // 🛡️ Ne révèle pas si l'utilisateur existe
        if (!$user) {
            return $this->redirectToRoute('app_check_email');
        }

        try {
            $resetToken = $this->resetPasswordHelper->generateResetToken($user);
        } catch (ResetPasswordExceptionInterface $e) {
            // Option : Informer l'utilisateur de l'erreur
            // ⚠️ Attention : peut révéler si l'utilisateur existe
            // 
            // $this->addFlash('reset_password_error', sprintf(
            //     '%s - %s',
            //     $translator->trans(...),
            //     $translator->trans($e->getReason(), [], 'ResetPasswordBundle')
            // ));

            return $this->redirectToRoute('app_check_email');
        }

        // Utilisation de TemplatedEmail pour un email HTML stylisé
        $email = (new TemplatedEmail())
            ->from(new Address('contact@hsn.com', 'HSN'))
            ->to((string) $user->getEmail())
            ->subject('Your password reset request')
            ->htmlTemplate('reset_password/email.html.twig')
            ->context([
                'resetToken' => $resetToken,
            ])
        ;

        $mailer->send($email);

        // Stocke l'objet token en session pour la route check-email
        $this->setTokenObjectInSession($resetToken);

        return $this->redirectToRoute('app_check_email');
    }
}
```

### 3.5 Analyse détaillée du contrôleur Reset Password

#### 🔧 **ResetPasswordControllerTrait - Les méthodes magiques**

```php
use ResetPasswordControllerTrait;
```

**Ce que ce trait vous apporte automatiquement :**

| Méthode | Rôle | Quand l'utiliser |
|---------|------|------------------|
| `storeTokenInSession($token)` | Stocke le token en session | Après validation du lien email |
| `getTokenFromSession()` | Récupère le token de la session | Pour valider le token |
| `getTokenObjectFromSession()` | Récupère l'objet token complet | Page de confirmation |
| `setTokenObjectInSession($resetToken)` | Stocke l'objet token | Après génération du token |
| `removeTokenFromSession()` | Supprime le token | Après changement de mot de passe |
| `cleanSessionAfterReset()` | Nettoie toute la session | Après succès |

**Pourquoi utiliser un trait ?**
- Évite la duplication de code
- Code testé et maintenu par le bundle
- Garantit la cohérence du comportement

---

#### 📍 **Constructeur - Injection de dépendances**

```php
public function __construct(
    private ResetPasswordHelperInterface $resetPasswordHelper,
    private EntityManagerInterface $entityManager
) {}
```

**🔍 Explications :**

| Service | Rôle | Utilisation |
|---------|------|-------------|
| `ResetPasswordHelperInterface` | Service principal du bundle | Génère, valide et supprime les tokens |
| `EntityManagerInterface` | Gestionnaire de base de données | Persiste les modifications dans la BD |

**💡 Pourquoi l'injection de dépendances ?**
- Symfony injecte automatiquement ces services
- Facilite les tests unitaires
- Respect du principe SOLID (Dependency Inversion)

---

#### 📝 **Méthode request() - Demande de réinitialisation**

```php
#[Route('/reset-password', name: 'app_forgot_password_request')]
public function request(
    Request $request, 
    MailerInterface $mailer, 
    UserRepository $userRepository
): Response
{
    // Si formulaire soumis (POST)
    if ($request->isMethod('POST')) {
        return $this->processSendingPasswordResetEmail(
            $request->request->get('email'),  // Récupère l'email du formulaire
            $mailer,
            $userRepository
        );
    }

    // Sinon, afficher le formulaire (GET)
    return $this->render('reset_password/request.html.twig');
}
```

**🔍 Explications ligne par ligne :**

1. **`#[Route('/reset-password', name: 'app_forgot_password_request')]`**
    - Définit l'URL de la page
    - Nom de route pour les redirections

2. **`Request $request`**
    - Objet contenant toutes les données de la requête HTTP
    - Permet de savoir si c'est GET ou POST

3. **`MailerInterface $mailer`**
    - Service d'envoi d'emails de Symfony
    - Utilisé pour envoyer le lien de réinitialisation

4. **`UserRepository $userRepository`**
    - Repository pour accéder aux utilisateurs en base
    - Permet de vérifier si l'email existe

5. **`$request->isMethod('POST')`**
    - Vérifie si le formulaire a été soumis
    - GET = affichage, POST = traitement

6. **`$request->request->get('email')`**
    - Récupère la valeur du champ email du formulaire
    - Équivalent à `$_POST['email']` en PHP natif

---

#### 🔐 **Méthode processSendingPasswordResetEmail() - Traitement sécurisé**

```php
private function processSendingPasswordResetEmail(
    string $emailFormData, 
    MailerInterface $mailer, 
    UserRepository $userRepository
): Response
{
```

**Étape 1 : Recherche de l'utilisateur**

```php
$user = $userRepository->findOneBy(['email' => $emailFormData]);

// ⚠️ SÉCURITÉ : Ne jamais révéler si l'email existe
if (!$user) {
    return $this->redirectToRoute('app_check_email');
}
```

**🔍 Pourquoi ne pas afficher "Email inexistant" ?**

| ❌ Mauvaise pratique | ✅ Bonne pratique |
|---------------------|-------------------|
| "Cet email n'existe pas" | "Si votre email existe, vous recevrez un lien" |
| **Risque** : Un attaquant peut découvrir les emails enregistrés | **Sécurité** : Impossible de savoir si l'email existe |

**Étape 2 : Génération du token**

```php
try {
    $resetToken = $this->resetPasswordHelper->generateResetToken($user);
} catch (ResetPasswordExceptionInterface $e) {
    // En cas d'erreur, rediriger sans message
    return $this->redirectToRoute('app_check_email');
}
```

**🔍 Que fait `generateResetToken()` ?**

1. Génère un token cryptographiquement sûr (ex: `a7b3c9d2e5f8...`)
2. Crée une entrée dans la table `reset_password_request`
3. Associe le token à l'utilisateur
4. Définit la date d'expiration (selon config : 1 heure)

**Structure du token en base :**

| Colonne | Exemple | Description |
|---------|---------|-------------|
| `id` | 1 | Identifiant unique |
| `user_id` | 42 | ID de l'utilisateur |
| `selector` | `abc123...` | Partie publique du token |
| `hashed_token` | `$2y$13$...` | Token hashé (sécurité) |
| `requested_at` | `2025-09-30 14:30:00` | Date de création |
| `expires_at` | `2025-09-30 15:30:00` | Date d'expiration |

**Étape 3 : Envoi de l'email**

```php
$email = (new Email())
    ->from('hello@example.com')          // Adresse d'expédition
    ->to($user->getEmail())              // Destinataire
    ->subject('Demande de réinitialisation de mot de passe')
    ->html($this->renderView('reset_password/email.html.twig', [
        'resetToken' => $resetToken,     // Passe le token à la vue
    ]));

$mailer->send($email);
```

**🔍 Contenu du token :**

```php
// $resetToken contient :
$resetToken->getToken();        // Token complet pour l'URL
$resetToken->getExpiresAt();    // Date d'expiration
$resetToken->getUser();         // L'utilisateur concerné
```

**Exemple d'URL générée :**
```
https://monsite.com/reset-password/reset/abc123def456ghi789jkl012mno345
```

---

#### 🔄 **Méthode reset() - Réinitialisation du mot de passe**

**Partie 1 : Gestion du token dans l'URL**

```php
#[Route('/reset-password/reset/{token}', name: 'app_reset_password')]
public function reset(
    Request $request, 
    UserPasswordHasherInterface $passwordHasher, 
    string $token = null
): Response
{
    // Si token présent dans l'URL
    if ($token) {
        // Stocker en session pour sécurité
        $this->storeTokenInSession($token);
        // Rediriger sans le token dans l'URL
        return $this->redirectToRoute('app_reset_password');
    }
```

**🔍 Pourquoi stocker en session ?**

| Problème sans session | Solution avec session |
|----------------------|----------------------|
| Token visible dans l'URL | Token invisible dans l'URL |
| Risque de partage accidentel | Sécurité renforcée |
| Historique du navigateur | Pas de trace |

**Exemple de flux :**

```
1. Utilisateur clique sur le lien email :
   https://monsite.com/reset-password/reset/TOKEN123

2. Le contrôleur intercepte :
   - Stocke TOKEN123 en session
   - Redirige vers https://monsite.com/reset-password/reset

3. Le token n'est plus visible dans l'URL
```

**Partie 2 : Récupération et validation du token**

```php
    // Récupérer le token depuis la session
    $token = $this->getTokenFromSession();
    if (null === $token) {
        throw $this->createNotFoundException('Token de réinitialisation introuvable.');
    }

    // Valider le token et récupérer l'utilisateur
    try {
        $user = $this->resetPasswordHelper->validateTokenAndFetchUser($token);
    } catch (ResetPasswordExceptionInterface $e) {
        $this->addFlash('reset_password_error', 'Token invalide ou expiré.');
        return $this->redirectToRoute('app_forgot_password_request');
    }
```

**🔍 Que fait `validateTokenAndFetchUser()` ?**

Le bundle effectue **5 vérifications** :

1. ✅ **Le token existe** dans la base de données
2. ✅ **Le token n'a pas expiré** (< 1 heure par défaut)
3. ✅ **Le token correspond** au hash en base
4. ✅ **L'utilisateur existe** toujours
5. ✅ **Le token n'a pas déjà été utilisé**

**Exceptions possibles :**

```php
catch (ResetPasswordExceptionInterface $e) {
    // Types d'erreurs :
    // - TooManyPasswordRequestsException : Trop de demandes
    // - ExpiredResetPasswordTokenException : Token expiré
    // - InvalidResetPasswordTokenException : Token invalide
}
```

**Partie 3 : Changement du mot de passe**

```php
    // Si formulaire soumis avec nouveau mot de passe
    if ($request->isMethod('POST')) {
        // 1. Nettoyer la session
        $this->removeTokenFromSession();

        // 2. Récupérer le nouveau mot de passe
        $plainPassword = $request->request->get('plainPassword');
        
        // 3. Hasher le mot de passe (bcrypt/argon2)
        $encodedPassword = $passwordHasher->hashPassword($user, $plainPassword);
        
        // 4. Mettre à jour l'utilisateur
        $user->setPassword($encodedPassword);
        
        // 5. Supprimer le token de la base (usage unique)
        $this->resetPasswordHelper->removeResetRequest($token);
        
        // 6. Sauvegarder en base de données
        $this->entityManager->flush();
        
        // 7. Nettoyer complètement la session
        $this->cleanSessionAfterReset();

        // 8. Rediriger vers la page de connexion
        return $this->redirectToRoute('app_login');
    }

    // Afficher le formulaire de nouveau mot de passe
    return $this->render('reset_password/reset.html.twig', [
        'resetForm' => null,
    ]);
}
```

**🔍 Explications détaillées :**

**1. Nettoyage de la session**
```php
$this->removeTokenFromSession();
```
- Supprime le token de la session
- Évite la réutilisation

**2. Hashage du mot de passe**
```php
$encodedPassword = $passwordHasher->hashPassword($user, $plainPassword);
```
- Utilise bcrypt ou argon2id (selon config)
- Le mot de passe n'est **jamais stocké en clair**
- Exemple de hash : `$2y$13$abcdefg...xyz123`

**3. Suppression du token**
```php
$this->resetPasswordHelper->removeResetRequest($token);
```
- **Usage unique** : Un token ne peut servir qu'une fois
- Supprime l'entrée de `reset_password_request`
- Sécurité : Impossible de réutiliser le lien

**4. Persistance en base**
```php
$this->entityManager->flush();
```
- Enregistre toutes les modifications
- Transaction ACID (Atomique)

---

### 3.6 Workflow complet - Diagramme de séquence

```mermaid
sequenceDiagram
    participant U as Utilisateur
    participant F as Formulaire
    participant C as Controller
    participant H as ResetPasswordHelper
    participant DB as Base de données
    participant M as Mailer

    Note over U,M: ÉTAPE 1 : Demande de réinitialisation
    U->>F: Saisit son email
    F->>C: POST /reset-password
    C->>DB: Recherche utilisateur
    DB-->>C: Utilisateur trouvé
    C->>H: generateResetToken(user)
    H->>DB: Enregistre token + expiration
    DB-->>H: Token créé
    H-->>C: Retourne ResetPasswordToken
    C->>M: Envoie email avec lien
    M-->>U: Email reçu

    Note over U,M: ÉTAPE 2 : Clic sur le lien
    U->>C: GET /reset-password/reset/TOKEN
    C->>C: storeTokenInSession(TOKEN)
    C-->>U: Redirect /reset-password/reset

    Note over U,M: ÉTAPE 3 : Affichage du formulaire
    U->>C: GET /reset-password/reset
    C->>C: getTokenFromSession()
    C->>H: validateTokenAndFetchUser(token)
    H->>DB: Vérification token
    DB-->>H: Token valide
    H-->>C: Retourne User
    C-->>U: Affiche formulaire nouveau mdp

    Note over U,M: ÉTAPE 4 : Soumission nouveau mot de passe
    U->>C: POST nouveau mot de passe
    C->>C: hashPassword(newPassword)
    C->>H: removeResetRequest(token)
    H->>DB: Supprime token
    C->>DB: Met à jour user.password
    DB-->>C: Sauvegardé
    C-->>U: Redirect /login
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
    B --> C{identifiants valides?}
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

## 🔧 6. Dépannage

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
