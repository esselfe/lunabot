#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>

#include "lunabot.h"
#include "liblunabot.h"

// Function to verify the GitHub webhook signature
int VerifySignature_func(const char *payload, const char *signature) {
	if (libglobals->debug)
		fprintf(stderr, "VerifySignature() started\n");

	unsigned int hash_len = 32;
	unsigned char hash[hash_len];
	char *secret_env = getenv("LUNABOT_WEBHOOK_SECRET");
	char secret[BUFFER_SIZE];

	unsigned int secret_len = 0;
	if (secret_env != NULL)
		secret_len = strlen(secret_env);

	if (secret_env == NULL || secret_len == 0) {
		memset(secret, 0, BUFFER_SIZE);

		FILE *fp = fopen(".secret", "r");
		if (fp == NULL) {
			Log(LOCAL, "lunabot::VerifySignature(): .secret file not found!");
			exit(1);
		}
		else {
			fgets(secret, BUFFER_SIZE - 1, fp);
			fclose(fp);

			// Strip newline ending
			if (secret[strlen(secret)-1] == '\n')
				secret[strlen(secret)-1] = '\0';
		}
	}
	else
		snprintf(secret, BUFFER_SIZE - 1, "%s", secret_env);

	HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)payload,
		strlen(payload), hash, &hash_len);

	char computed_signature[128];
	memset(computed_signature, 0, 128);
	snprintf(computed_signature, sizeof(computed_signature), "sha256=");
	for (int i = 0; i < hash_len; i++)
		snprintf(computed_signature + strlen(computed_signature), 3,
			"%02x", hash[i]);

	if (strlen(signature) != strlen(computed_signature))
		return 1;

	// Prevent timing attack
	unsigned int is_invalid = 0;
	unsigned int is_dummy = 0;
	for (int i = 0; i < strlen(signature); i++) {
		if (signature[i] != computed_signature[i])
			is_invalid = 1;
		else
			is_dummy = 0;
	}
	return is_invalid;
}

