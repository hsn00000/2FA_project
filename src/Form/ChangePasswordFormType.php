<?php

namespace App\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\NotCompromisedPassword;
use Symfony\Component\Validator\Constraints\PasswordStrength;

// Ce formulaire permet à l'utilisateur de saisir et confirmer son nouveau mot de passe lors de la réinitialisation.

class ChangePasswordFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            // Le visiteur doit saisir et confirmer son nouveau mot de passe.
            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'options' => [
                    'attr' => [
                        'autocomplete' => 'new-password',
                    ],
                ],
                // Configuration des deux champs de mot de passe
                // 'first_options' pour le premier champ
                // 'second_options' pour le second champ
                'first_options' => [


                    // Controle de la robustesse du mot de passe
                    'constraints' => [
                        // NotBlank → interdit un mot de passe vide.
                        new NotBlank([
                            'message' => 'Please enter a password',
                        ]),
                        // Length(min=12) → impose une longueur minimale (12 caractères).
                        new Length([
                            'min' => 8,
                            'minMessage' => 'Your password should be at least {{ limit }} characters',
                            // max length allowed by Symfony for security reasons
                            'max' => 4096,
                        ]),
                        // PasswordStrength() → impose une complexité (majuscules, chiffres, caractères spéciaux…).
                        new PasswordStrength([
                            'minScore' => PasswordStrength::STRENGTH_WEAK,
                        ]),
                        // NotCompromisedPassword() → vérifie que le mot de passe n’apparaît pas dans une base de données de mots de passe piratés.
                        new NotCompromisedPassword(),
                    ],
                    'label' => 'New password',
                ],
                'second_options' => [
                    'label' => 'Repeat Password',
                ],
                'invalid_message' => 'The password fields must match.',
                // Instead of being set onto the object directly,
                // this is read and encoded in the controller
                'mapped' => false,
            ])
        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([]);
    }
}
