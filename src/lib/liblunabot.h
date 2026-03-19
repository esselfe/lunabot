
#include "lunabot.h"

extern struct GlobalVariables *libglobals;

// From src/lib/irc.c
void SendIrcMessage(const char *message);

// From src/lib/log.c
void Log(unsigned int direction, char *text);

// From src/lib/verify-signature.c
int VerifySignature_func(const char *payload, const char *signature);

