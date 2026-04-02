#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <time.h>
#include <pthread.h>
#include <microhttpd.h>

#include "lunabot.h"
#include "liblunabot.h"

static void *HealthCheckTimeoutFunc(void *argp) {
	time_t current, start = time(NULL);
	while (libglobals->health_check == 1) {
		current = time(NULL);
		if (current > start + 10) {
			libglobals->health_check = -1;
			break;
		}
		else
			sleep(1);
	}
	
	return NULL;
}

static void HealthCheckTimeoutStart(void) {
	pthread_t health_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&health_thread, &attr, HealthCheckTimeoutFunc, NULL);
	pthread_detach(health_thread);
	pthread_attr_destroy(&attr);
}

enum MHD_Result HandleHealthCheck(struct MHD_Connection *connection) {
	// Ratelimit requests to prevent abuse
	libglobals->health_check_t0 = time(NULL);
	if (libglobals->health_check_t0 >
	  libglobals->health_check_tprev + libglobals->health_check_wait) {
		libglobals->health_check_tprev = libglobals->health_check_t0;

		libglobals->health_check = 1;
		char buffer2[BUFFER_SIZE];
		sprintf(buffer2, "PING NickServ\r\n");
		SSL_write(libglobals->pSSL, buffer2, strlen(buffer2));

		HealthCheckTimeoutStart();

		while (libglobals->health_check == 1)
			sleep(1);
	}
	else {
		sleep(1);
		libglobals->health_check = 2;
	}

	if (libglobals->health_check < 0) {
		libglobals->health_check = 0;
		char *data = "<html><body><h2>500 Service error</h2></body></html>";
		struct MHD_Response *response500;
		response500 = MHD_create_response_from_buffer(strlen(data),
				data, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, 500, response500);
		MHD_destroy_response(response500);
		return ret;
	}

	libglobals->health_check = 0;
	char *data = "<html><body><h2>200 OK</h2></body></html>";
	struct MHD_Response *response200;
	response200 = MHD_create_response_from_buffer(strlen(data),
			data, MHD_RESPMEM_PERSISTENT);
	int ret = MHD_queue_response(connection, 200, response200);
	MHD_destroy_response(response200);
	return ret;
}

