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

