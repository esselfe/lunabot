#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "lunabot.h"
#include "liblunabot.h"

// Function to send messages to the IRC channel
void SendIrcMessage(const char *message) {
	Log(OUT, (char *)message);
	char buffer_msg[BUFFER_SIZE * 16];
	snprintf(buffer_msg, sizeof(buffer_msg), "PRIVMSG %s :%s\r\n",
		libglobals->channel, message);
	SSL_write(libglobals->pSSL, buffer_msg, strlen(buffer_msg));
}

