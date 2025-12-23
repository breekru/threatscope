<?php
declare(strict_types=1);

final class PasswordPolicy
{
    public static function validate(string $pw): array
    {
        $errors = [];

        if (strlen($pw) < 10) {
            $errors[] = 'Password must be at least 10 characters.';
        }
        if (!preg_match('/[A-Z]/', $pw)) {
            $errors[] = 'Password must include at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $pw)) {
            $errors[] = 'Password must include at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $pw)) {
            $errors[] = 'Password must include at least one number.';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $pw)) {
            $errors[] = 'Password must include at least one special character.';
        }

        return $errors;
    }
}
