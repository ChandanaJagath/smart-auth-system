<?php

declare(strict_types=1);

/**
 * Email via PHPMailer (SMTP). Install: composer require phpmailer/phpmailer
 *
 * Forgot password: set MAIL_USE_MOCK=false, MAIL_HOST, MAIL_USER, MAIL_PASS (Gmail: app password).
 */
final class MailService
{
    public function __construct(
        private readonly array $mailConfig,
        private readonly string $publicUrl
    ) {
    }

    /**
     * Password reset link email (forgot password flow).
     */
    public function sendResetEmail(string $toEmail, string $token): bool
    {
        $link = $this->buildResetLink($token);
        $subject = 'Reset your password';
        $html = '<p>Click the link below to reset your password:</p>'
            . '<p><a href="' . htmlspecialchars($link, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">Reset password</a></p>'
            . '<p>This link expires in 1 hour. If you did not request a reset, you can ignore this email.</p>';
        $text = "Click the link below to reset your password:\n\n{$link}\n\nThis link expires in 1 hour.";
        $toName = $this->displayNameFromEmail($toEmail);

        return $this->deliver($toEmail, $toName, $subject, $html, $text);
    }

    public function sendVerificationEmail(string $toEmail, string $toName, string $token): bool
    {
        $link = $this->publicUrl . '/verify.html?token=' . rawurlencode($token);
        $subject = 'Verify your email';
        $safeName = htmlspecialchars($toName, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $body = '<p>Hello ' . $safeName . ',</p><p>Please verify your email by opening this link:</p>'
            . '<p><a href="' . htmlspecialchars($link, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">Verify email</a></p>'
            . '<p>This link expires in 1 hour.</p>';
        $text = "Hello {$toName},\n\nVerify your email: {$link}\n\nThis link expires in 1 hour.";

        return $this->deliver($toEmail, $toName, $subject, $body, $text);
    }

    /** Same reset link as sendResetEmail(), with a personalized greeting (name in body). */
    public function sendPasswordResetEmail(string $toEmail, string $toName, string $token): bool
    {
        $link = $this->buildResetLink($token);
        $subject = 'Reset your password';
        $safeName = htmlspecialchars($toName, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $body = '<p>Hello ' . $safeName . ',</p><p>Click the link below to reset your password:</p>'
            . '<p><a href="' . htmlspecialchars($link, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">Reset password</a></p>'
            . '<p>This link expires in 1 hour. If you did not request this, ignore this email.</p>';
        $text = "Hello {$toName},\n\nClick the link below to reset your password:\n\n{$link}\n\nExpires in 1 hour.";

        return $this->deliver($toEmail, $toName, $subject, $body, $text);
    }

    private function buildResetLink(string $token): string
    {
        return $this->publicUrl . '/reset.html?token=' . rawurlencode($token);
    }

    private function displayNameFromEmail(string $email): string
    {
        $local = strstr($email, '@', true);

        return $local !== false && $local !== '' ? $local : 'User';
    }

    private function deliver(string $toEmail, string $toName, string $subject, string $htmlBody, string $textBody): bool
    {
        $useMock = !empty($this->mailConfig['use_mock']);
        $mailerClass = '\PHPMailer\PHPMailer\PHPMailer';
        $hasMailer = class_exists($mailerClass);

        if ($useMock) {
            error_log(sprintf(
                '[MailService mock] To=%s Subject=%s (set MAIL_USE_MOCK=false and configure SMTP to send real mail)',
                $toEmail,
                $subject
            ));
            return true;
        }

        if (!$hasMailer) {
            error_log('[MailService] PHPMailer not found. Run: composer install (from project root).');
            return false;
        }

        $host = trim((string) ($this->mailConfig['host'] ?? ''));
        if ($host === '') {
            error_log('[MailService] MAIL_HOST is empty. Set MAIL_HOST (e.g. smtp.gmail.com) or use MAIL_USE_MOCK=true.');
            return false;
        }

        $user = trim((string) ($this->mailConfig['user'] ?? ''));
        $pass = (string) ($this->mailConfig['pass'] ?? '');
        if ($user === '' || $pass === '') {
            error_log('[MailService] MAIL_USER / MAIL_PASS required for SMTP when MAIL_USE_MOCK=false.');
            return false;
        }

        try {
            return $this->sendViaPhpmailer($mailerClass, $toEmail, $toName, $subject, $htmlBody, $textBody);
        } catch (Throwable $e) {
            error_log('[MailService] SMTP send failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * @param class-string $mailerClass
     */
    private function sendViaPhpmailer(
        string $mailerClass,
        string $toEmail,
        string $toName,
        string $subject,
        string $htmlBody,
        string $textBody
    ): bool {
        /** @var \PHPMailer\PHPMailer\PHPMailer $mail */
        $mail = new $mailerClass(true);
        $mail->CharSet = 'UTF-8';
        $mail->isSMTP();
        $mail->Host = (string) ($this->mailConfig['host'] ?? '');
        $mail->Port = (int) ($this->mailConfig['port'] ?? 587);
        $mail->SMTPAuth = true;
        $mail->Username = trim((string) ($this->mailConfig['user'] ?? ''));
        $mail->Password = (string) ($this->mailConfig['pass'] ?? '');

        $enc = strtolower((string) ($this->mailConfig['encryption'] ?? 'tls'));
        if ($enc === 'tls') {
            $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        } elseif ($enc === 'ssl') {
            $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        } else {
            $mail->SMTPSecure = '';
        }

        $debug = (int) ($this->mailConfig['debug'] ?? 0);
        if ($debug > 0) {
            $mail->SMTPDebug = min(4, max(1, $debug));
            $mail->Debugoutput = 'error_log';
        }

        $fromEmail = trim((string) ($this->mailConfig['from_email'] ?? ''));
        if ($fromEmail === '') {
            $fromEmail = $mail->Username;
        }
        $fromName = (string) ($this->mailConfig['from_name'] ?? 'Smart Auth');
        $mail->setFrom($fromEmail, $fromName);
        $mail->addAddress($toEmail, $toName);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body = $htmlBody;
        $mail->AltBody = $textBody;

        $mail->send();
        return true;
    }
}
