#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#include "lunabot.h"
#include "liblunabot.h"

// Function to send messages to the IRC channel
void SendIrcMessage(const char *message) {
	char buffer_msg[BUFFER_SIZE * 16];
	snprintf(buffer_msg, sizeof(buffer_msg), "PRIVMSG %s :%s\r\n",
		libglobals->channel, message);

	pthread_mutex_lock(&libglobals->irc_write_mutex);
	if (libglobals->pSSL == NULL || !libglobals->irc_ready) {
		pthread_mutex_unlock(&libglobals->irc_write_mutex);
		Log(LOCAL, "liblunabot::SendIrcMessage() warning: IRC connection is not ready");
		return;
	}
	Log(OUT, (char *)message);
	SSL_write(libglobals->pSSL, buffer_msg, strlen(buffer_msg));
	pthread_mutex_unlock(&libglobals->irc_write_mutex);
}
