/*
 * Secure Password Handling Module
 * Replaces insecure crypt() with modern password hashing
 *
 * [SECURITY] This module provides secure password hashing and verification
 * to replace the legacy crypt() function which uses DES encryption.
 * Maintains backward compatibility with existing password storage.
 */

#ifndef SECURE_PASSWORD_H
#define SECURE_PASSWORD_H

#include <stdbool.h>

/*
 * [SECURITY] Modern password hashing using SHA-256 with salt
 * Replaces insecure DES-based crypt()
 */

/* Generate a secure salt for password hashing */
char *generate_salt(void);

/* Hash a password with the provided salt */
char *hash_password(const char *password, const char *salt);

/* Verify a password against a stored hash */
bool verify_password(const char *password, const char *stored_hash);

/* Legacy compatibility function - converts old crypt() hashes to new format */
char *migrate_legacy_password(const char *legacy_hash);

/* Check if a hash is in legacy format */
bool is_legacy_hash(const char *hash);

#endif /* SECURE_PASSWORD_H */
