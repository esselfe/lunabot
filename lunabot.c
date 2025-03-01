/* IRC bot for Github webhook notifications
   Copyrighted Stephane Fontaine 2025 under GPLv3
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <microhttpd.h>
#include <jansson.h>

#define SERVER "irc.libera.chat"
#define PORT 6697
#define NICK "lunabot"
#define CHANNEL "#lunar"
#define WEBHOOK_PORT 3000

const char *lunabot_version = "0.1.3";

unsigned int mainloopend;
int irc_sock;
char server_ip[16];
SSL *pSSL;
#define BUFFER_SIZE 1024
char buffer[BUFFER_SIZE];
char buffer_log[BUFFER_SIZE * 4];
struct MHD_Daemon *httpdaemon;
unsigned int ignore_pending = 1;
// IRC color codes
#define NORMAL      "\003"   // default/restore
#define BLACK       "\00301"
#define BLUE        "\00302"
#define GREEN       "\00303"
#define RED         "\00304"
#define BROWN       "\00305"
#define PURPLE      "\00306"
#define ORANGE      "\00307"
#define YELLOW      "\00308"
#define LIGHT_GREEN "\00309"
#define CYAN        "\00310"
#define LIGHT_CYAN  "\00311"
#define LIGHT_BLUE  "\00312"
#define PINK        "\00313"
#define GREY        "\00314"
#define LIGHT_GREY  "\00315"

// Logging directions, to help parsing output using << || >>
#define LOCAL 0
#define IN    1
#define OUT   2
char *log_filename = "lunabot.log";

void Log(unsigned int direction, char *text) {
	FILE *log_fp = fopen(log_filename, "a+");
	if (log_fp == NULL) {
		fprintf(stderr, "lunabot::Log() error: Cannot open '%s': %s\n",
			log_filename, strerror(errno));
		exit(1);
	}

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

	fprintf(log_fp, "%04d%02d%02d-%02d:%02d:%02d.%06ld %s##%s##\n",
		tm0->tm_year+1900, tm0->tm_mon+1, tm0->tm_mday,
		tm0->tm_hour, tm0->tm_min, tm0->tm_sec, tv0.tv_usec,
		dirstr, text);

	// Show message in console with colors
	fprintf(stdout, "\033[00;36m%04d%02d%02d-%02d:%02d:%02d.%06ld %s"
		"##\033[00m%s\033[00;36m##\033[00m\n", 
		tm0->tm_year+1900, tm0->tm_mon+1, tm0->tm_mday,
		tm0->tm_hour, tm0->tm_min, tm0->tm_sec, tv0.tv_usec,
		dirstr, text);
	
	fclose(log_fp);
}

char *GetIP(char *hostname) {
	struct addrinfo hints, *res, *p;
	int status;
	void *addr;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // Use AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC for both
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		sprintf(buffer_log, "lunabot::GetIP() error: getaddrinfo() failed: %s", gai_strerror(status));
		Log(LOCAL, buffer_log);
		return NULL;
	}

	// Loop through results and pick the first one
	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) { // IPv4
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
			inet_ntop(p->ai_family, addr, server_ip, sizeof(server_ip));
			freeaddrinfo(res); // Cleanup
			return server_ip;
		}
		else
			continue;
	}

	freeaddrinfo(res);
	return NULL; // No IP found

}

// Function to send messages to the IRC channel
void SendIrcMessage(const char *message) {
	Log(OUT, (char *)message);
	char buffer_msg[4096];
	snprintf(buffer_msg, sizeof(buffer_msg), "PRIVMSG %s :%s\r\n", CHANNEL, message);
	SSL_write(pSSL, buffer_msg, strlen(buffer_msg));
}

// IRC connection thread
void *IrcConnect(void *arg) {
	struct sockaddr_in server_addr;

	// Create socket
	irc_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (irc_sock < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: socket() failed: %s", strerror(errno));
		Log(LOCAL, buffer_log);
		exit(1);
	}

	char *ret = GetIP(SERVER);
	if (ret == NULL) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: Cannot get an IP for '%s'", SERVER);
		Log(LOCAL, buffer_log);
		close(irc_sock);
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);

	// Connect to IRC server
	if (connect(irc_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: connect() failed: %s", strerror(errno));
		Log(LOCAL, buffer_log);
		close(irc_sock);
		exit(1);
	}

	// Setup TLS with the new connection
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	const SSL_METHOD *method = TLS_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		Log(LOCAL, "lunabot::IrcConnect() error: Cannot create SSL context");
		close(irc_sock);
		exit(1);
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	pSSL = SSL_new(ctx);
	SSL_set_options(pSSL, SSL_OP_NO_COMPRESSION);

	BIO *bio = BIO_new_socket(irc_sock, BIO_CLOSE);
	SSL_set_bio(pSSL, bio, bio);
	SSL_set1_host(pSSL, SERVER);
	SSL_connect(pSSL);

	// Send basic IRC commands
	sprintf(buffer, "NICK %s\r\n", NICK);
	SSL_write(pSSL, buffer, strlen(buffer));

	sprintf(buffer, "USER %s 0 * :GitHub PR IRC bot\r\n", NICK);
	SSL_write(pSSL, buffer, strlen(buffer));

	FILE *fp = fopen(".passwd", "r");
	if (fp == NULL) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: Cannot open .passwd: %s", strerror(errno));
		Log(LOCAL, buffer_log);
		exit(1);
	}
	else {
		char pass[BUFFER_SIZE - 30];
		fgets(pass, BUFFER_SIZE - 31, fp);
		fclose(fp);
		if (pass[strlen(pass)-1] == '\n')
			pass[strlen(pass)-1] = '\0';
		sprintf(buffer, "PRIVMSG NickServ :IDENTIFY %s\r\n", pass);
		Log(OUT, "PRIVMSG NickServ :IDENTIFY ********");
		SSL_write(pSSL, buffer, strlen(buffer));
	}
// Not logged in yet, exposes hostmask, needs to be sent manually in the terminal
//	sprintf(buffer, "JOIN %s\r\n", CHANNEL);
//	SSL_write(pSSL, buffer, strlen(buffer));

	// Listen for server messages
	while (1) {
		char buffer2[BUFFER_SIZE*2];
		memset(buffer, 0, BUFFER_SIZE);
		int bytes = SSL_read(pSSL, buffer, BUFFER_SIZE - 1);
		if (bytes <= 0)
			break;

		if (buffer[bytes-1] == '\n')
			buffer[bytes-1] = '\0';   // Remove '\n'
		if (buffer[bytes-2] == '\r')
			buffer[bytes-2] = '\0'; // Remove '\r'
		
		Log(IN, buffer);
		
		// Respond to ping requests with a pong message
		if (strncmp(buffer, "PING", 4) == 0) {
			sprintf(buffer_log, "PONG %s", buffer + 5);
			Log(OUT, buffer_log);
			sprintf(buffer2, "PONG %s\r\n", buffer + 5);
			SSL_write(pSSL, buffer2, strlen(buffer2));
		}
	}

	close(irc_sock);
	exit(0);
	return NULL;
}

// Function to verify the GitHub webhook signature
int VerifySignature(const char *payload, const char *signature) {
	unsigned int hash_len = 32;
	unsigned char hash[hash_len];
	char secret[1024];

	FILE *fp = fopen(".secret", "r");
	if (fp == NULL) {
		Log(LOCAL, "lunabot::VerifySignature(): .secret file not found!");
		exit(1);
	}
	else {
		fgets(secret, 1023, fp);
		fclose(fp);
		
		// Strip newline ending
		if (secret[strlen(secret)-1] == '\n')
			secret[strlen(secret)-1] = '\0';
	}

	HMAC(EVP_sha256(), secret, strlen(secret), (unsigned char*)payload, strlen(payload),
		hash, &hash_len);

	char computed_signature[128];
	memset(computed_signature, 0, 128);
	snprintf(computed_signature, sizeof(computed_signature), "sha256=");
	for (int i = 0; i < hash_len; i++)
		snprintf(computed_signature + strlen(computed_signature), 3, "%02x", hash[i]);

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
	json_t *root;
	json_error_t error;
	root = json_loads(json_data, 0, &error);

	if (!root) {
		sprintf(buffer_log, "JSON parsing error: %s", error.text);
		Log(LOCAL, buffer_log);
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
			if (ignore_pending) {
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
			sprintf(status_str, "%s", "Failed");
			color = RED;
		}

		char message[512];
		snprintf(message, sizeof(message),
			"[%s%s%s]: '%s' %s",
			color, status_str, NORMAL,
			json_string_value(msg), 
			json_string_value(target_url));
		SendIrcMessage(message);
		free(status_str);
	
		return;
	}
	
	// Process PR ops
	json_t *action = json_object_get(root, "action");
	json_t *pr = json_object_get(root, "pull_request");
	if (json_is_string(action) && json_is_object(pr)) {
		if (strcmp(json_string_value(action), "opened") == 0) {
			json_t *title = json_object_get(pr, "title");
			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");

			if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
				char message[512];
				snprintf(message, sizeof(message), 
						 "[%sNew PR%s]: '%s' from %s - %s",
						 GREEN, NORMAL,
						 json_string_value(title), 
						 json_string_value(user), 
						 json_string_value(url));
				SendIrcMessage(message);
			}
		}
		else if (strcmp(json_string_value(action), "closed") == 0) {
			json_t *title = json_object_get(pr, "title");
			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");
			json_t *is_merged = json_object_get(pr, "merged");
			if (is_merged != NULL && json_is_true(is_merged)) {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					char message[512];
					snprintf(message, sizeof(message),
						"[%sMerged PR%s]: '%s' from %s - %s",
						CYAN, NORMAL,
						json_string_value(title),
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(message);
				}
			}
			else {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					char message[512];
					snprintf(message, sizeof(message),
						"[%sClosed PR%s]: '%s' from %s - %s",
						RED, NORMAL,
						json_string_value(title),
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(message);
				}
			}
		}
	}
	else
		Log(LOCAL, "Got webhook data without a conditional branch for it!");

	json_decref(root);
}

// HTTP request handler
static enum MHD_Result WebhookCallback(void *cls, struct MHD_Connection *connection, 
		const char *url, const char *method, 
		const char *version, const char *upload_data,
		unsigned long *upload_data_size, void **ptr) {
	static char *json_buffer = NULL;
	static size_t total_size = 0;
	static unsigned int cnt = 0;

	const char *signature = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Hub-Signature-256");
	if (!signature) {
		char *data = "<html><body><h2>401 Unauthorized</h2></body></html>";
		struct MHD_Response *response401;
		response401 = MHD_create_response_from_buffer(strlen(data),
				data, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, 401, response401);
		MHD_destroy_response(response401);
		Log(LOCAL, "Webhook signature verification failed!");
		return ret;
	}

	// On first call, initialize buffer
	if (*ptr == NULL) {
		json_buffer = malloc(16384); // Initial allocation (adjust as needed)
		if (!json_buffer) {
			Log(LOCAL, "lunabot::WebhookCallback() error: Cannot allocate memory");
			return MHD_NO;
		}
		memset(json_buffer, 0, 16384);
		total_size = 0;
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
		if (new_size >= 16384) {  // Adjust buffer size if needed
			char *temp = realloc(json_buffer, new_size + 1);
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

		if (VerifySignature(json_buffer, signature)) {
			char *data = "<html><body><h2>401 Unauthorized</h2></body></html>";
			struct MHD_Response *response401;
			response401 = MHD_create_response_from_buffer (strlen(data), data,
                                            MHD_RESPMEM_PERSISTENT);
			int ret = MHD_queue_response(connection, 401, response401);
			MHD_destroy_response(response401);
			Log(LOCAL, "Webhook signature verification failed!");
			return ret;
		}

		ParseJsonData(json_buffer);
	}

	// Clean up and send response
	free(json_buffer);
	*ptr = NULL;
	total_size = 0;
	cnt = 0;

	struct MHD_Response *response = MHD_create_response_from_buffer(16, "OK", MHD_RESPMEM_PERSISTENT);
	int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	
	return ret;
}

// Webhook server thread
void WebhookServerStart(void) {
	httpdaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, WEBHOOK_PORT, NULL, NULL,
							  &WebhookCallback, NULL, MHD_OPTION_END);
	if (!httpdaemon) {
		Log(LOCAL, "lunabot::WebhookServerStart(): Failed to start HTTP server");
		exit(1);
	}
	else {
		sprintf(buffer_log, "Webhook server running on port %d", WEBHOOK_PORT);
		Log(LOCAL, buffer_log);
	}
}

// Program entry point
int main() {
	WebhookServerStart();

	pthread_t irc_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&irc_thread, &attr, IrcConnect, NULL);
	pthread_detach(irc_thread);
	pthread_attr_destroy(&attr);

	// Start reading user input from the terminal and process per-line
	char buffer_line[BUFFER_SIZE];
	while(!mainloopend) {
		memset(buffer_line, 0, BUFFER_SIZE);
		char *ret = fgets(buffer_line, BUFFER_SIZE - 3, stdin);
		if (ret == NULL)
			continue;
		else {
			if (buffer_line[strlen(buffer_line) - 1] == '\n')
				buffer_line[strlen(buffer_line) - 1] = '\0';
		}

		if (strncmp(buffer_line, "exit", 4) == 0 || strcmp(buffer_line, "quit") == 0 ||
		  strncmp(buffer_line, "qw", 2) == 0) {
			mainloopend = 1;
			Log(LOCAL, "lunabot exited");
		}
		else if (strlen(buffer_line) > 0 && *buffer_line != '\n') {
			Log(OUT, buffer_line);
			// Send to server, this is a raw message!
			char buffer2[BUFFER_SIZE * 2];
			memset(buffer2, 0, BUFFER_SIZE * 2);
			sprintf(buffer2, "%s\r\n", buffer_line);
			SSL_write(pSSL, buffer2, strlen(buffer2));
		}
	}

	MHD_stop_daemon(httpdaemon);
	return 0;
}

