#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <microhttpd.h>
#include <jansson.h>

#include "lunabot.h"

struct GlobalVariables *libglobals;

void Log(unsigned int direction, char *text) {
	char *dirstr;
	if (direction == LOCAL)
		dirstr = "||";
	else if (direction == IN)
		dirstr = "<<";
	else if (direction == OUT)
		dirstr = ">>";
	else
		dirstr = "!!";
	
	time_t t0 = time(NULL);
	struct tm *tm0 = gmtime(&t0);
	struct timeval tv0;
	gettimeofday(&tv0, NULL);

	// Show message in console with colors
	fprintf(stdout, "\033[00;36m%04d%02d%02d-%02d:%02d:%02d.%06ld %s"
		"##\033[00m%s\033[00;36m##\033[00m\n", 
		tm0->tm_year+1900, tm0->tm_mon+1, tm0->tm_mday,
		tm0->tm_hour, tm0->tm_min, tm0->tm_sec, tv0.tv_usec,
		dirstr, text);
	
	if (libglobals->disable_logging)
		return;

	FILE *log_fp = fopen(libglobals->log_filename, "a+");
	if (log_fp == NULL) {
		fprintf(stderr, "lunabot::Log() error: Cannot open '%s': %s\n",
			libglobals->log_filename, strerror(errno));
		exit(1);
	}
	
	fprintf(log_fp, "%04d%02d%02d-%02d:%02d:%02d.%06ld %s##%s##\n",
		tm0->tm_year+1900, tm0->tm_mon+1, tm0->tm_mday,
		tm0->tm_hour, tm0->tm_min, tm0->tm_sec, tv0.tv_usec,
		dirstr, text);

	fclose(log_fp);
}

// Function to send messages to the IRC channel
void SendIrcMessage(const char *message) {
	Log(OUT, (char *)message);
	char buffer_msg[BUFFER_SIZE * 16];
	snprintf(buffer_msg, sizeof(buffer_msg), "PRIVMSG %s :%s\r\n",
		libglobals->channel, message);
	SSL_write(libglobals->pSSL, buffer_msg, strlen(buffer_msg));
}

// Function to verify the GitHub webhook signature
int VerifySignature_func(const char *payload, const char *signature) {
	if (libglobals->debug)
		fprintf(stderr, "VerifySignature() started\n");

	unsigned int hash_len = 32;
	unsigned char hash[hash_len];
	char *secret_env = (char *)getenv("LUNABOT_WEBHOOK_SECRET");
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
		sprintf(secret, "%s", secret_env);

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

void ParseJsonData(char *json_data) {
	if (libglobals->debug)
		fprintf(stderr, "ParseJsonData() started\n");

	char buffer[BUFFER_SIZE];
	json_t *root;
	json_error_t error;
	root = json_loads(json_data, 0, &error);

	if (!root) {
		sprintf(buffer, "JSON parsing error: %s", error.text);
		Log(LOCAL, buffer);
		return;
	}

	// Process CI build statuses
	json_t *context = json_object_get(root, "context");
	if (json_is_string(context)) {
		if (strcmp(json_string_value(context), "default") != 0) {
			json_decref(root);
			return;
		}

		json_t *status = json_object_get(root, "state");
		if (!json_is_string(status)) {
			json_decref(root);
			return;
		}
		json_t *target_url = json_object_get(root, "target_url");
		// Wait for the second event, the first one doesn't have target_url set
		if (json_is_string(target_url) && strlen(json_string_value(target_url)) == 0) {
			json_decref(root);
			return;
		}
		json_t *commit_outer = json_object_get(root, "commit");
		if (!json_is_object(commit_outer)) {
			json_decref(root);
			return;
		}
		json_t *commit_inner = json_object_get(commit_outer, "commit");
		if (!json_is_object(commit_inner)) {
			json_decref(root);
			return;
		}
		json_t *msg = json_object_get(commit_inner, "message");
		if (!json_is_string(msg)) {
			json_decref(root);
			return;
		}
		char *color;
		char *status_str = strdup(json_string_value(status));
		if (strcmp(status_str, "pending") == 0) {
			// Reduce message volume and skip those
			if (libglobals->ignore_pending) {
				free(status_str);
				json_decref(root);
				return;
			}
			*status_str = 'P';
			color = YELLOW;
		}
		else if (strcmp(status_str, "success") == 0) {
			*status_str = 'S';
			color = GREEN;
		}
		else if (strcmp(status_str, "failure") == 0) {
			snprintf(buffer, sizeof(buffer),
				"[%sFailed%s]:    '%s' %s",
				RED, NORMAL,
				json_string_value(msg),
				json_string_value(target_url));
			SendIrcMessage(buffer);
			free(status_str);

			json_decref(root);
			return;
		}

		snprintf(buffer, sizeof(buffer),
			"[%s%s%s]:   '%s' %s",
			color, status_str, NORMAL,
			json_string_value(msg), 
			json_string_value(target_url));
		SendIrcMessage(buffer);
		free(status_str);
	
		json_decref(root);
		return;
	}
	
	// Process PR ops
	json_t *action = json_object_get(root, "action");
	json_t *pr = json_object_get(root, "pull_request");
	if (json_is_string(action) && json_is_object(pr)) {
		if (strcmp(json_string_value(action), "labeled") == 0) {
			if (libglobals->ignore_labels) {
				json_decref(root);
				return;
			}

			if (libglobals->only_core_labels) {
				json_t *repo = json_object_get(root, "repository");
				if (json_is_object(repo)) {
					json_t *repo_name = json_object_get(repo, "name");
					if (json_is_string(repo_name)) {
						if (strcmp(json_string_value(repo_name),
						  "moonbase-core") != 0) {
							json_decref(root);
							return;
						}
					}
				}
			}

			json_t *sender = json_object_get(root, "sender");
			if (json_is_object(sender)) {
				json_t *username = json_object_get(sender, "login");
				json_t *title = json_object_get(pr, "title");
				json_t *url = json_object_get(pr, "html_url");
				json_t *label = json_object_get(root, "label");
				json_t *label_name = json_object_get(label, "name");
				snprintf(buffer, sizeof(buffer), 
					"[%sLabels%s]:    %s added the '%s' label to '%s' - %s",
					LIGHT_GREEN, NORMAL,
					json_string_value(username),
					json_string_value(label_name),
					json_string_value(title), 
					json_string_value(url));
				SendIrcMessage(buffer);
				json_decref(root);
				return;
			}
		}
		else if (strcmp(json_string_value(action), "unlabeled") == 0) {
			if (libglobals->ignore_labels) {
				json_decref(root);
				return;
			}

			if (libglobals->only_core_labels) {
				json_t *repo = json_object_get(root, "repository");
				if (json_is_object(repo)) {
					json_t *repo_name = json_object_get(repo, "name");
					if (json_is_string(repo_name)) {
						if (strcmp(json_string_value(repo_name),
						  "moonbase-core") != 0) {
							json_decref(root);
							return;
						}
					}
				}
			}

			json_t *sender = json_object_get(root, "sender");
			if (json_is_object(sender)) {
				json_t *username = json_object_get(sender, "login");
				json_t *title = json_object_get(pr, "title");
				json_t *url = json_object_get(pr, "html_url");
				json_t *label = json_object_get(root, "label");
				json_t *label_name = json_object_get(label, "name");
				snprintf(buffer, sizeof(buffer), 
					"[%sLabels%s]:    %s removed the '%s' label to '%s' - %s",
					LIGHT_GREEN, NORMAL,
					json_string_value(username),
					json_string_value(label_name),
					json_string_value(title), 
					json_string_value(url));
				SendIrcMessage(buffer);
				json_decref(root);
				return;
			}
		}
		else if (strcmp(json_string_value(action), "opened") == 0) {
			json_t *title = json_object_get(pr, "title");
			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");

			if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
				snprintf(buffer, sizeof(buffer), 
					"[%sNew PR%s]:    '%s' from %s - %s",
					GREEN, NORMAL,
					json_string_value(title), 
					json_string_value(user), 
					json_string_value(url));
				SendIrcMessage(buffer);
				json_decref(root);
				return;
			}
		}
		else if (strcmp(json_string_value(action), "closed") == 0) {
			json_t *title = json_object_get(pr, "title");
			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");
			json_t *is_merged = json_object_get(pr, "merged");
			if (is_merged != NULL && json_is_true(is_merged)) {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					snprintf(buffer, sizeof(buffer),
						"[%sMerged PR%s]: '%s' from %s - %s",
						CYAN, NORMAL,
						json_string_value(title),
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(buffer);
					json_decref(root);
					return;
				}
			}
			else {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					snprintf(buffer, sizeof(buffer),
						"[%sClosed PR%s]: '%s' from %s - %s",
						RED, NORMAL,
						json_string_value(title),
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(buffer);
					json_decref(root);
					return;
				}
			}
		}
	}
	
	// Process push commits
	json_t *ref = json_object_get(root, "refs");
	json_t *commits = json_object_get(root, "commits");
	json_t *committer;
	json_t *username;
	json_t *msg;
	json_t *url;
	if (ref != NULL && commits != NULL) {
		if (libglobals->ignore_commits) {
			json_decref(root);
			return;
		}
		
		if (strcmp(json_string_value(ref), "refs/head/master") != 0) {
			json_decref(root);
			return;
		}

		int arrlen = json_array_size(commits);
		int cnt;
		for (cnt = 0; cnt < arrlen; cnt++) {
			json_t *arrobj = json_array_get(commits, cnt);
			
			committer = json_object_get(arrobj, "committer");
			if (json_is_object(committer))
				username = json_object_get(committer, "username");	

			msg = json_object_get(arrobj, "message");
			url = json_object_get(arrobj, "url");
			
			if (json_is_string(username) && json_is_string(msg) &&
			  json_is_string(url)) {
				snprintf(buffer, sizeof(buffer),
					"[%sCommits%s]:   '%s' from %s - %s",
					CYAN, NORMAL,
					json_string_value(msg),
					json_string_value(username),
					json_string_value(url));
				SendIrcMessage(buffer);
				json_decref(root);
				return;
			}
		}
	}

	Log(LOCAL, "Got webhook data without a conditional branch for it!");

	json_decref(root);
}

void *HealthCheckTimeoutFunc(void *argp) {
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

void HealthCheckTimeoutStart(void) {
	pthread_t health_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&health_thread, &attr, HealthCheckTimeoutFunc, NULL);
	pthread_detach(health_thread);
	pthread_attr_destroy(&attr);
}

// HTTP request handler
enum MHD_Result WebhookCallback(void *cls, struct MHD_Connection *connection, 
		const char *url, const char *method, 
		const char *version, const char *upload_data,
		unsigned long *upload_data_size, void **ptr) {
	static char *json_buffer = NULL;
	static unsigned int json_buffer_size = BUFFER_SIZE * 16;
	static size_t total_size = 0;
	static unsigned int cnt = 0;
	
	if (url) {
		if (strcmp(method, MHD_HTTP_METHOD_GET) == 0 &&
			strcmp(url, "/health") == 0) {
			libglobals->health_check = 1;
			char buffer2[BUFFER_SIZE];
			sprintf(buffer2, "PING NickServ\r\n");
			SSL_write(libglobals->pSSL, buffer2, strlen(buffer2));
			
			HealthCheckTimeoutStart();
			
			while (libglobals->health_check == 1)
				sleep(1);
			
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
			else if (libglobals->health_check > 1) {
				libglobals->health_check = 0;
				char *data = "<html><body><h2>200 OK</h2></body></html>";
				struct MHD_Response *response200;
				response200 = MHD_create_response_from_buffer(strlen(data),
						data, MHD_RESPMEM_PERSISTENT);
				int ret = MHD_queue_response(connection, 200, response200);
				MHD_destroy_response(response200);
				return ret;
			}
		}
	}
	
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
}

