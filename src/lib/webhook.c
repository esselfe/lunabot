#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <microhttpd.h>

#include "lunabot.h"
#include "liblunabot.h"

// HTTP request handler
enum MHD_Result WebhookCallback(void *cls, struct MHD_Connection *connection,
		const char *url, const char *method,
		const char *version, const char *upload_data,
		unsigned long *upload_data_size, void **ptr) {
	static char *json_buffer = NULL;
	static unsigned int json_buffer_size = BUFFER_SIZE * 16;
	static size_t total_size = 0;
	static unsigned int cnt = 0;

	if (url && strcmp(method, MHD_HTTP_METHOD_GET) == 0 &&
	  strcmp(url, "/health") == 0)
		return HandleHealthCheck(connection);
	
	// Only accept POST requests
	if (strcmp(method, MHD_HTTP_METHOD_POST) != 0) {
		char *data = "<html><body><h2>401 Unauthorized</h2></body></html>";
		struct MHD_Response *response401;
		response401 = MHD_create_response_from_buffer(strlen(data),
				data, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, 401, response401);
		MHD_destroy_response(response401);
		return ret;
	}

	const char *signature = MHD_lookup_connection_value(connection,
					MHD_HEADER_KIND, "X-Hub-Signature-256");
	if (!signature) {
		char *data = "<html><body><h2>401 Unauthorized</h2></body></html>";
		struct MHD_Response *response401;
		response401 = MHD_create_response_from_buffer(strlen(data),
				data, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, 401, response401);
		MHD_destroy_response(response401);
		Log(LOCAL, "Webhook signature missing from the HTTP header!");
		return ret;
	}

	// On first call, initialize buffer
	if (*ptr == NULL) {
		json_buffer = malloc(json_buffer_size); // Initial allocation (adjust as needed)
		if (!json_buffer) {
			Log(LOCAL, "lunabot::WebhookCallback() error: Cannot allocate memory");
			return MHD_NO;
		}
		memset(json_buffer, 0, json_buffer_size);
		total_size = 0;
		cnt = 0;
		*ptr = json_buffer;
	}

	// First pass is empty
	if (*upload_data_size == 0 && cnt == 0)
		return MHD_YES; // Continue receiving
	// If there is new data, append it to the buffer
	else if (*upload_data_size > 0) {
		++cnt;
		size_t new_size = total_size + *upload_data_size;

		// Reallocate buffer if needed
		if (new_size >= json_buffer_size) {  // Adjust buffer size if needed
			json_buffer_size = new_size + 1;
			char *temp = realloc(json_buffer, json_buffer_size);
			if (!temp) {
				Log(LOCAL, "lunabot::WebhookCallback() error: Cannot allocate memory");
				free(json_buffer);
				return MHD_NO;
			}
			json_buffer = temp;
			*ptr = json_buffer;
		}

		// Append new data
		memcpy(json_buffer + total_size, upload_data, *upload_data_size);
		total_size += *upload_data_size;
		json_buffer[total_size] = '\0'; // Null-terminate

		*upload_data_size = 0;
		return MHD_YES; // Continue receiving
	}
	// If we have all data, process JSON
	else if (*upload_data_size == 0 && cnt >= 1) {
		Log(LOCAL, "Received full webhook JSON:");
		Log(IN, json_buffer);

		cnt = 0;

		if (VerifySignature_func(json_buffer, signature)) {
			char *data = "<html><body><h2>401 Unauthorized</h2></body></html>";
			struct MHD_Response *response401;
			response401 = MHD_create_response_from_buffer(strlen(data),
					data, MHD_RESPMEM_PERSISTENT);
			int ret = MHD_queue_response(connection, 401, response401);
			MHD_destroy_response(response401);
			Log(LOCAL, "Webhook signature verification failed!");
			return ret;
		}

		ParseJsonData(json_buffer);
	}

	// Clean up and send response
	free(json_buffer);
	json_buffer_size = BUFFER_SIZE * 16;
	*ptr = NULL;
	total_size = 0;
	cnt = 0;

	struct MHD_Response *response = MHD_create_response_from_buffer(16, "OK", MHD_RESPMEM_PERSISTENT);
	int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	
	return ret;
}

