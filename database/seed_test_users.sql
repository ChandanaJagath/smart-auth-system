-- =============================================================================
-- Test users (local / staging only). Change passwords before any production use.
--   admin@gmail.com  → role admin  → password: admin123
--   user@gmail.com   → role user   → password: user123
-- Run after full_setup.sql or migrations. Safe to re-run (upserts by email).
-- =============================================================================

INSERT INTO `users` (`name`, `email`, `password`, `is_verified`, `verification_token`, `verification_expires`, `role`)
VALUES
  ('Test Admin', 'admin@gmail.com', '$2y$10$9ALdAI6qkSPhM7mhKHwoJO9ipl4IbEmbJHf0r2RcXslnDTtbvZw2y', 1, NULL, NULL, 'admin'),
  ('Test User', 'user@gmail.com', '$2y$10$m6uY.It6OZ798lkMA3Dvle2nKKYpL7mCV49v1fGZm.gFlELF/WyHa', 1, NULL, NULL, 'user')
ON DUPLICATE KEY UPDATE
  `name` = VALUES(`name`),
  `password` = VALUES(`password`),
  `is_verified` = VALUES(`is_verified`),
  `verification_token` = VALUES(`verification_token`),
  `verification_expires` = VALUES(`verification_expires`),
  `role` = VALUES(`role`);
