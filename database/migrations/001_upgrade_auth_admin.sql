-- Upgrade existing smart_auth database (run once if you installed before full_setup.sql / role columns)
-- USE smart_auth;

ALTER TABLE `users`
  ADD COLUMN `is_verified` TINYINT(1) NOT NULL DEFAULT 0 AFTER `password`,
  ADD COLUMN `verification_token` VARCHAR(255) NULL DEFAULT NULL AFTER `is_verified`,
  ADD COLUMN `verification_expires` DATETIME NULL DEFAULT NULL AFTER `verification_token`,
  ADD COLUMN `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user' AFTER `verification_expires`;

-- Mark existing accounts as verified so they can still log in
UPDATE `users` SET `is_verified` = 1 WHERE `is_verified` = 0;

ALTER TABLE `users` ADD KEY `users_verification_token` (`verification_token`);

CREATE TABLE IF NOT EXISTS `password_resets` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `email` VARCHAR(255) NOT NULL,
  `token` VARCHAR(64) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `password_resets_token_unique` (`token`),
  KEY `password_resets_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional: promote first user to admin (uncomment if desired)
-- UPDATE `users` SET `role` = 'admin' ORDER BY `id` ASC LIMIT 1;
