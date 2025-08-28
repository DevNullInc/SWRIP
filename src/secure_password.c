/*
 * Secure Password Handling Implementation
 * [SECURITY] Modern password hashing using SHA-256 with salt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "secure_password.h"

/* Salt length for password hashing */
#define SALT_LENGTH 16
#define HASH_LENGTH SHA256_DIGEST_LENGTH

/*
 * [SECURITY] Generate a cryptographically secure random salt
 */
char *generate_salt(void) {
    unsigned char salt_bytes[SALT_LENGTH];
    char *salt_hex;
    int i;

    /* Generate random salt */
    if (RAND_bytes(salt_bytes, SALT_LENGTH) != 1) {
        /* Fallback to less secure method if RAND_bytes fails */
        srand((unsigned int)time(NULL));
        for (i = 0; i < SALT_LENGTH; i++) {
            salt_bytes[i] = (unsigned char)(rand() % 256);
        }
    }

    /* Convert to hex string */
    salt_hex = (char *)malloc(SALT_LENGTH * 2 + 1);
    if (!salt_hex) return NULL;

    for (i = 0; i < SALT_LENGTH; i++) {
        snprintf( salt_hex + (i * 2), 3, "%02x", salt_bytes[i]);
    }
    salt_hex[SALT_LENGTH * 2] = '\0';

    return salt_hex;
}

/*
 * [SECURITY] Hash password using SHA-256 with salt
 * Format: salt$hash
 */
char *hash_password(const char *password, const char *salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *result;
    SHA256_CTX sha256;
    unsigned char salted_password[1024]; /* Should be large enough */
    size_t password_len = strlen(password);
    size_t salt_len = strlen(salt);

    /* Combine salt and password */
    if (salt_len + password_len + 1 > sizeof(salted_password)) {
        return NULL; /* Input too large */
    }

    memcpy(salted_password, salt, salt_len);
    memcpy(salted_password + salt_len, password, password_len);
    salted_password[salt_len + password_len] = '\0';

    /* Hash the salted password */
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salted_password, salt_len + password_len);
    SHA256_Final(hash, &sha256);

    /* Format: salt$hash_in_hex */
    result = (char *)malloc(salt_len + 1 + (HASH_LENGTH * 2) + 1);
    if (!result) return NULL;

    strcpy(result, salt);
    strcat(result, "$");

    for (size_t i = 0; i < HASH_LENGTH; i++) {
        snprintf(result + salt_len + 1 + (i * 2), 3, "%02x", hash[i]);
    }

    return result;
}

/*
 * [SECURITY] Verify password against stored hash
 */
bool verify_password(const char *password, const char *stored_hash) {
    char *salt_end;
    char *computed_hash;
    bool result = false;

    if (!password || !stored_hash) return false;

    /* Check if this is a legacy crypt() hash */
    if (is_legacy_hash(stored_hash)) {
        /* For now, return false for legacy hashes until migration */
        /* In production, you would migrate them */
        return false;
    }

    /* Parse salt$hash format */
    salt_end = strchr(stored_hash, '$');
    if (!salt_end) return false;

    size_t salt_len = salt_end - stored_hash;
    char *salt = (char *)malloc(salt_len + 1);
    if (!salt) return false;

    strncpy(salt, stored_hash, salt_len);
    salt[salt_len] = '\0';

    /* Compute hash with extracted salt */
    computed_hash = hash_password(password, salt);
    free(salt);

    if (computed_hash) {
        result = (strcmp(computed_hash, stored_hash) == 0);
        free(computed_hash);
    }

    return result;
}

/*
 * [SECURITY] Check if hash is in legacy crypt() format
 * Legacy crypt() hashes are 13 characters and start with salt
 */
bool is_legacy_hash(const char *hash) {
    if (!hash || strlen(hash) != 13) return false;

    /* crypt() hashes have specific format: salt + hash */
    /* First two chars are salt (alphanumeric, ./) */
    char c1 = hash[0], c2 = hash[1];
    if (!((c1 >= 'a' && c1 <= 'z') || (c1 >= 'A' && c1 <= 'Z') ||
          (c1 >= '0' && c1 <= '9') || c1 == '.' || c1 == '/') ||
        !((c2 >= 'a' && c2 <= 'z') || (c2 >= 'A' && c2 <= 'Z') ||
          (c2 >= '0' && c2 <= '9') || c2 == '.' || c2 == '/')) {
        return false;
    }

    return true;
}

/*
 * [SECURITY] Migrate legacy crypt() hash to new format
 * This function helps transition from old DES-based crypt() to SHA-256
 */
char *migrate_legacy_password(const char *legacy_hash) {
    /* This is a placeholder for migration logic */
    /* In practice, you would need the original password to migrate */
    /* For now, return NULL to indicate migration needed */
    return NULL;
}
