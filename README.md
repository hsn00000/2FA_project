🔐 Authentification à deux facteurs (2FA) avec Google Authenticator – Symfony

Documentation basée sur le bundle SchebTwoFactorBundle
.
Ce guide explique pas à pas comment installer, configurer et activer la 2FA avec Google Authenticator dans un projet Symfony.

⚙️ 1) Installation du projet Symfony

Cloner le dépôt :

git clone <url-du-repo>
cd <nom-du-projet>


Installer les dépendances :

composer install


Configurer l’environnement :

Copier .env → .env.local

Configurer la base de données

Créer la base de données :

symfony console doctrine:database:create


Exécuter les migrations :

symfony console doctrine:migrations:migrate


Lancer le serveur Symfony :

symfony server:start -d


Créer un utilisateur de test :

symfony console app:add-user user@example.com motdepasse --role ROLE_ADMIN

🔧 2) Installation du bundle 2FA

Installer le bundle principal et Google Authenticator :

composer require scheb/2fa-bundle scheb/2fa-google-authenticator


(Optionnel) Ajouter d’autres fonctionnalités :

composer require scheb/2fa-backup-code
composer require scheb/2fa-trusted-device


Vérifier que le bundle est bien activé dans config/bundles.php :

return [
    // ...
    Scheb\TwoFactorBundle\SchebTwoFactorBundle::class => ['all' => true],
];

🛣️ 3) Configuration des routes

Créer le fichier config/routes/scheb_2fa.yaml :

2fa_login:
    path: /2fa
    controller: "scheb_two_factor.form_controller::form"

2fa_login_check:
    path: /2fa_check

🛡️ 4) Configuration de la sécurité (security.yaml)

Configurer le firewall pour activer la 2FA :

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
            two_factor:
                auth_form_path: 2fa_login
                check_path: 2fa_login_check

📦 5) Configuration du bundle (scheb_two_factor.yaml)

Créer le fichier config/packages/scheb_two_factor.yaml :

scheb_two_factor:
    security_tokens:
        - Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken

    google:
        enabled: true
        server_name: "MonProjetSymfony"
        issuer: "MonProjet"
        digits: 6
        window: 1

👤 6) Mise à jour de l’entité User

L’entité User doit implémenter TwoFactorInterface.

use Scheb\TwoFactorBundle\Model\Google\TwoFactorInterface;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class User implements UserInterface, PasswordAuthenticatedUserInterface, TwoFactorInterface
{
    #[ORM\Column(type: 'boolean')]
    private bool $isGoogleAuthenticatorEnabled = false;

    #[ORM\Column(type: 'string', nullable: true)]
    private ?string $googleAuthenticatorSecret = null;

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


⚠️ Après modification :

symfony console make:migration
symfony console doctrine:migrations:migrate

🔑 7) Génération du secret Google Authenticator

Exemple de commande Symfony pour activer la 2FA et générer un QR Code :

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

    protected function configure()
    {
        $this->addArgument('email', InputArgument::REQUIRED, 'Email de l’utilisateur');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $email = $input->getArgument('email');
        $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user) {
            $output->writeln("<error>Utilisateur introuvable</error>");
            return Command::FAILURE;
        }

        $secret = $this->googleAuthenticator->generateSecret();
        $user->setGoogleAuthenticatorSecret($secret)->enableGoogleAuthenticator();
        $this->em->flush();

        $qrCodeUrl = $this->googleAuthenticator->getQRContent($user);
        $output->writeln("2FA activée pour $email");
        $output->writeln("Ajoutez ce QR Code à Google Authenticator :");
        $output->writeln($qrCodeUrl);

        return Command::SUCCESS;
    }
}


Exécution :

symfony console app:enable-2fa user@example.com

🔄 8) Workflow utilisateur

L’utilisateur se connecte avec email + mot de passe.

Symfony redirige vers /2fa.

L’utilisateur saisit le code temporaire généré par Google Authenticator.

✅ Connexion validée si le code est correct.

🛠️ 9) Options supplémentaires

Codes de secours : scheb/2fa-backup-code

Appareils de confiance : scheb/2fa-trusted-device

Exemple de config :

scheb_two_factor:
    backup_codes:
        enabled: true
        codes: 10
        length: 6
    trusted_device:
        enabled: true
        lifetime: 2592000 # 30 jours
