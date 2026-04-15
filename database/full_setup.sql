-- =============================================================================
-- Smart Auth System — full_setup.sql
-- =============================================================================
-- One file for fresh installs AND upgrades (idempotent, non-destructive).
--
-- Requirements: MySQL 8.0.12+ (uses ADD COLUMN IF NOT EXISTS).
-- Safe to run multiple times. No DROP TABLE / destructive DDL.
--
-- remember_tokens column names match backend/helpers/RememberMe.php:
--   token_hash  = SHA-256 hash of the cookie validator (opaque secret)
--   expires_at  = when the remember-me row expires
-- =============================================================================

-- =============================================================================
-- DATABASE SETUP
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `smart_auth`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `smart_auth`;

-- =============================================================================
-- USERS TABLE
-- =============================================================================
-- Base columns: id, name, email, password
-- Plus: verification, role, created_at (added via ALTER if missing on upgrade)

CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(100) NOT NULL,
  `email` VARCHAR(150) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `is_verified` TINYINT(1) NOT NULL DEFAULT 0,
  `verification_token` VARCHAR(255) NULL DEFAULT NULL,
  `verification_expires` DATETIME NULL DEFAULT NULL,
  `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `users_email_unique` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Upgrade path: add any column missing on older databases (keeps existing data)
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `is_verified` TINYINT(1) NOT NULL DEFAULT 0 AFTER `password`;
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `verification_token` VARCHAR(255) NULL DEFAULT NULL AFTER `is_verified`;
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `verification_expires` DATETIME NULL DEFAULT NULL AFTER `verification_token`;
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user' AFTER `verification_expires`;
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER `role`;

-- Optional index for verification lookups (create only if missing)
SET @idx_exists := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'users'
    AND INDEX_NAME = 'users_verification_token'
);
SET @sql_idx_users := IF(
  @idx_exists = 0,
  'ALTER TABLE `users` ADD INDEX `users_verification_token` (`verification_token`)',
  'SELECT 1'
);
PREPARE stmt_idx_users FROM @sql_idx_users;
EXECUTE stmt_idx_users;
DEALLOCATE PREPARE stmt_idx_users;

-- =============================================================================
-- PASSWORD RESETS TABLE
-- =============================================================================

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

ALTER TABLE `password_resets` ADD COLUMN IF NOT EXISTS `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER `expires_at`;

-- =============================================================================
-- REMEMBER TOKENS TABLE (RememberMe.php)
-- =============================================================================
-- Stores selector + hashed validator; FK to users.id ON DELETE CASCADE

CREATE TABLE IF NOT EXISTS `remember_tokens` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` INT UNSIGNED NOT NULL,
  `selector` CHAR(32) NOT NULL,
  `token_hash` CHAR(64) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `remember_tokens_selector_unique` (`selector`),
  KEY `remember_tokens_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `remember_tokens` ADD COLUMN IF NOT EXISTS `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER `expires_at`;

-- Foreign key only if not already present (idempotent)
SET @fk_exists := (
  SELECT COUNT(*)
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'remember_tokens'
    AND CONSTRAINT_NAME = 'remember_tokens_user_id_fk'
    AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql_fk_remember := IF(
  @fk_exists = 0,
  'ALTER TABLE `remember_tokens` ADD CONSTRAINT `remember_tokens_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE',
  'SELECT 1'
);
PREPARE stmt_fk_remember FROM @sql_fk_remember;
EXECUTE stmt_fk_remember;
DEALLOCATE PREPARE stmt_fk_remember;

-- =============================================================================
-- LEGACY ACCOUNTS (pre–email-verification)
-- =============================================================================
-- Rows with no pending verification token are treated as already verified.

UPDATE `users`
SET `is_verified` = 1
WHERE `verification_token` IS NULL
  AND `verification_expires` IS NULL
  AND `is_verified` = 0;

-- =============================================================================
-- DEFAULT ADMIN USER
-- =============================================================================
-- Login: admin@example.com / admin123  — CHANGE PASSWORD IN PRODUCTION.
-- Password: bcrypt (PASSWORD_BCRYPT) for literal "admin123".

INSERT INTO `users` (
  `name`,
  `email`,
  `password`,
  `is_verified`,
  `verification_token`,
  `verification_expires`,
  `role`
)
SELECT
  'Admin',
  'admin@example.com',
  '$2y$10$APhw45tbjFqAgO5TvB5o7O58D8284S2ocqF2PwWcHWMxSvXSsbZsy',
  1,
  NULL,
  NULL,
  'admin'
FROM (SELECT 1 AS `_seed`) AS `_helper`
WHERE NOT EXISTS (
  SELECT 1 FROM `users` `u` WHERE `u`.`email` = 'admin@example.com' LIMIT 1
);

-- =============================================================================
-- END
-- =============================================================================
