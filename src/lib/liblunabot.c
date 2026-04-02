/* IRC bot for Github webhook notifications
   Copyrighted 2025-2026 GPLv3 (see the LICENSE file joined to this source code)
   Original author: Stephane Fontaine (esselfe)
   Contributor:     Stefan Wold (Ratler)
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <microhttpd.h>
#include <jansson.h>
#include <curl/curl.h>

#include "lunabot.h"
#include "liblunabot.h"

struct GlobalVariables *libglobals;

void FreeRawLine(struct RawLine *rawp) {
	if (rawp->nick != NULL)
		free(rawp->nick);
	if (rawp->username != NULL)
		free(rawp->username);
	if (rawp->host != NULL)
		free(rawp->host);
	if (rawp->command != NULL)
		free(rawp->command);
	if (rawp->channel != NULL)
		free(rawp->channel);
	if (rawp->text != NULL)
		free(rawp->text);

	free(rawp);
}

struct RawLine *ParseRawLine(char *line) {
	if (libglobals->debug)
		Log(LOCAL, "ParseRawLine() started");

	char buffer[BUFFER_SIZE];
	char *c = line;
	unsigned int cnt = 0;
	// Recording flags
	unsigned int rec_nick = 1, rec_username = 0, rec_host = 0;
	unsigned int rec_command = 0, rec_channel = 0, rec_text = 0;
	unsigned int word_size = 128;
	char word[word_size];
	
	// Messages to skip:
	if (strncmp(line, "NickServ!", 9) == 0 || strncmp(line, "ChanServ!", 9) == 0)
		return NULL;
	else if (strncmp(line, "PING :", 6) == 0)
		return NULL;
	else if (strncmp(line, "ERROR :", 7) == 0)
		return NULL;

	// Check the theorical raw.command field for raw lines to skip
	while (1) {
		if (*c == '\0')
			break;
		else if (*c == ' ') { // process at the first space encountered,
			++c;
			if ((*c >= '0' && *c <= '9') || strncmp(c, "MODE ", 5) == 0 ||
				strncmp(c, "NOTICE ", 7) == 0)
				return NULL;
			else if (strncmp(c, "PONG ", 5) == 0) {
				if (libglobals->health_check == 1) {
					libglobals->health_check = 2;
					return NULL;
				}
			}
			else
				break;
		}
		++c;
	}
	
	struct RawLine *rawp = malloc(sizeof(struct RawLine));
	if (rawp == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		return NULL;
	}
	else
		memset(rawp, 0, sizeof(struct RawLine));

	rawp->nick = malloc(word_size+1);
	if (rawp->nick == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}
	rawp->username = malloc(word_size+1);
	if (rawp->username == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}
	rawp->host = malloc(word_size+1);
	if (rawp->host == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}
	rawp->command = malloc(word_size+1);
	if (rawp->command == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}
	rawp->channel = malloc(word_size+1);
	if (rawp->channel == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}
	rawp->text = malloc(word_size+1);
	if (rawp->text == NULL) {
		Log(LOCAL, "lunabot::ParseRawLine(): Cannot allocate memory");
		FreeRawLine(rawp);
		return NULL;
	}

	c = line;
	unsigned int cnt_total = 0;
	while (1) {
		if (*c == ':' && cnt_total == 0) {
			memset(word, 0, word_size);
			++c;
			if (libglobals->debug) {
				sprintf(buffer, "  raw: <<%s>>", line);
				Log(LOCAL, buffer);
			}
			continue;
		}
		else if (rec_nick && *c == '!') {
			sprintf(rawp->nick, "%s", word);
			memset(word, 0, word_size);
			rec_nick = 0;
			rec_username = 1;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  nick: <%s>", rawp->nick);
				Log(LOCAL, buffer);
			}
		}
		else if (rec_username && cnt == 0 && *c == '~') {
			++c;
			continue;
		}
		else if (rec_username && *c == '@') {
			sprintf(rawp->username, "%s", word);
			memset(word, 0, word_size);
			rec_username = 0;
			rec_host = 1;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  username: <%s>", rawp->username);
				Log(LOCAL, buffer);
			}
		}
		else if (rec_host && *c == ' ') {
			sprintf(rawp->host, "%s", word);
			memset(word, 0, word_size);
			rec_host = 0;
			rec_command = 1;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  host: <%s>", rawp->host);
				Log(LOCAL, buffer);
			}
		}
		else if (rec_command && *c == ' ') {
			sprintf(rawp->command, "%s", word);
			memset(word, 0, word_size);
			rec_command = 0;
			rec_channel = 1;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  command: <%s>", rawp->command);
				Log(LOCAL, buffer);
			}
		}
		else if (rec_channel && *c == ' ') {
			sprintf(rawp->channel, "%s", word);
			memset(word, 0, word_size);
			rec_channel = 0;
			if (strcmp(rawp->command, "PRIVMSG") == 0)
				rec_text = 1;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  channel: <%s>", rawp->channel);
				Log(LOCAL, buffer);
			}
		}
		else if (rec_text && *c == '\0') {
			sprintf(rawp->text, "%s", word);
			memset(word, 0, word_size);
			rec_text = 0;
			cnt = 0;
			if (libglobals->debug) {
				sprintf(buffer, "  text: <%s>", rawp->text);
				Log(LOCAL, buffer);
			}
			break;
		}
		else {
			if (rec_text && *c == ':' && strlen(word) == 0) {
				++c;
				continue;
			}
			else
				word[cnt++] = *c;
		}

		++cnt_total;
		++c;
		if (!rec_text && (*c == '\0' || *c == '\n'))
			break;
	}

	if (libglobals->debug)
		Log(LOCAL, "ParseRawLine() ended\n");
	
	return rawp;
}

void liblunabotInit(void) {
	if (libglobals->httpdaemon != NULL)
		MHD_stop_daemon(libglobals->httpdaemon);

	libglobals->httpdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
				libglobals->webhook_port, NULL, NULL,
				WebhookCallback, NULL, MHD_OPTION_END);
	if (!libglobals->httpdaemon) {
		Log(LOCAL, "lunabot::WebhookServerStart(): Failed to start HTTP server");
		libglobals->mainloopend = 1;
	}
	else {
		char buffer[1024];
		sprintf(buffer, "Webhook server running on port %d",
			libglobals->webhook_port);
		Log(LOCAL, buffer);
	}
	
	libglobals->health_check_tprev = time(NULL) - libglobals->health_check_wait - 1;
}

