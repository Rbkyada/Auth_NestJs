/*
  Warnings:

  - You are about to drop the column `createdAt` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `firstName` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `hash` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `lastName` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `users` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE `users` DROP COLUMN `createdAt`,
    DROP COLUMN `firstName`,
    DROP COLUMN `hash`,
    DROP COLUMN `lastName`,
    DROP COLUMN `updatedAt`,
    ADD COLUMN `code` VARCHAR(255) NULL,
    ADD COLUMN `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `deleted_at` DATETIME(3) NULL,
    ADD COLUMN `first_name` VARCHAR(255) NULL,
    ADD COLUMN `is_onboarded` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `is_social_register` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `is_verified` BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN `last_name` VARCHAR(255) NULL,
    ADD COLUMN `logo` VARCHAR(255) NULL,
    ADD COLUMN `password` VARCHAR(255) NULL,
    ADD COLUMN `provider` VARCHAR(255) NULL,
    ADD COLUMN `provider_id` VARCHAR(255) NULL,
    ADD COLUMN `role` ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    ADD COLUMN `updated_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `username` VARCHAR(255) NULL;

-- CreateTable
CREATE TABLE `actions` (
    `id` INTEGER NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `actions_name_key`(`name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `logs` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `action_id` INTEGER NOT NULL,
    `user_id` INTEGER NOT NULL,
    `request_data` JSON NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `users_email_idx` ON `users`(`email`);

-- CreateIndex
CREATE INDEX `users_username_idx` ON `users`(`username`);

-- AddForeignKey
ALTER TABLE `logs` ADD CONSTRAINT `logs_action_id_fkey` FOREIGN KEY (`action_id`) REFERENCES `actions`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `logs` ADD CONSTRAINT `logs_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
