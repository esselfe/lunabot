#ifndef LIBLUNABOT_H
#define LIBLUNABOT_H 1

#include <jansson.h>

#include "lunabot.h"

extern struct GlobalVariables *libglobals;

// From src/lib/irc.c
void SendIrcMessage(const char *message);

// From src/lib/log.c
void Log(unsigned int direction, char *text);

// From src/lib/sanitize.c
char *SanitizeMessage(json_t *root, json_t *msg);

// From src/lib/verify-signature.c
int VerifySignature_func(const char *payload, const char *signature);
#endif /* LIBLUNABOT_H */
