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
#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <getopt.h>
#include <microhttpd.h>
#include <jansson.h>

#include "lunabot.h"
#include "liblunabot.h"

const char *lunabot_version_string = "0.6.4";

struct GlobalVariables globals, **globals_ptr;
char buffer[BUFFER_SIZE];
char buffer_log[BUFFER_SIZE * 4];

static const struct option long_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{"context", required_argument, NULL, 'C'},
	{"channel", required_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"irc-port", required_argument, NULL, 'p'},
	{"irc-server", required_argument, NULL, 's'},
	{"log", required_argument, NULL, 'l'},
	{"nick", required_argument, NULL, 'n'},
	{"webhook-port", required_argument, NULL, 'w'},
	{NULL, 0, NULL, 0}
};
static const char *short_options = "hVC:c:dl:n:p:s:w:";

void LunabotHelp(void) {
printf("lunabot option usage: lunabot --help/-h | --version/-V | --debug/-d |\n"
	"\t--channel/-c NAME | --nick/-n NAME | --irc-port/-p NUMBER |\n"
	"\t--irc-server/-s HOSTNAME | --log/-l FILENAME, off | \n"
	"\t--webhook-port/-w NUMBER | --context/-C NAME\n");
}

void *handle;
void (*Log_fp)(unsigned int direction, char *text);
void (*SendIrcMessage_fp)(const char *message);
void (*ReplayJsonPayload_fp)(char *filename);
void (*liblunabotInit_fp)(void);

void ReloadLibrary(void) {
	if (handle != NULL)
		dlclose(handle);

	// Try the libtool development build path first (where libtool places
	// the .so during in-tree builds), then fall back to the bare name so
	// the system dynamic linker can resolve it via ld.so.conf for installed
	// deployments.
	handle = dlopen("./src/lib/.libs/liblunabot.so", RTLD_LAZY);
	if (handle != NULL) {
		fprintf(stderr, "lunabot::ReloadLibrary() loaded ./src/lib/.libs/liblunabot.so\n");
	} else {
		handle = dlopen("liblunabot.so", RTLD_LAZY);
		if (handle != NULL) {
			fprintf(stderr, "lunabot::ReloadLibrary() loaded liblunabot.so (system path)\n");
		}
	}
	if (handle == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load liblunabot.so: %s\n",
			dlerror());
		exit(1);
	}

	// Link the main program's globals to the library pointer
	// so they can be used from the library functions
	globals_ptr = (struct GlobalVariables **)dlsym(handle, "libglobals");
	if (globals_ptr == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot find libglobals: %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
	*globals_ptr = &globals;
	
	*(void **)(&liblunabotInit_fp) = dlsym(handle, "liblunabotInit");
	if (liblunabotInit_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load liblunabotInit(): %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
	
	*(void **)(&Log_fp) = dlsym(handle, "Log");
	if (Log_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load Log(): %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
	
	*(void **)(&SendIrcMessage_fp) = dlsym(handle, "SendIrcMessage");
	if (SendIrcMessage_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load SendIrcMessage(): %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
	
	*(void **)(&ReplayJsonPayload_fp) = dlsym(handle, "ReplayJsonPayload");
	if (ReplayJsonPayload_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load ReplayJsonPayload(): %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
}

char *GetIP(char *hostname) {
	struct addrinfo hints, *res, *p;
	int status;
	void *addr;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // Use AF_INET for IPv4, AF_INET6 for IPv6, or AF_UNSPEC for both
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		sprintf(buffer_log, "lunabot::GetIP() error: getaddrinfo() failed: %s",
			gai_strerror(status));
		Log_fp(LOCAL, buffer_log);
		return NULL;
	}

	// Loop through results and pick the first one
	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) { // IPv4
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
			inet_ntop(p->ai_family, addr, globals.irc.irc_server_ip,
				sizeof(globals.irc.irc_server_ip));
			freeaddrinfo(res); // Cleanup
			return globals.irc.irc_server_ip;
		}
		else
			continue;
	}

	freeaddrinfo(res);
	return NULL; // No IP found

}

enum SaslState {
	SASL_WAIT_CAP_LS,
	SASL_WAIT_CAP_ACK,
	SASL_WAIT_AUTHENTICATE,
	SASL_WAIT_RESULT,
	SASL_AUTHENTICATED,
	SASL_COMPLETE,
	SASL_FAILED
};

struct SaslContext {
	enum SaslState state;
	int sasl_available;
	char *response;
	size_t response_len;
};

static int IrcWrite(const char *message) {
	int ret = -1;

	pthread_mutex_lock(&globals.irc_write_mutex);
	if (globals.pSSL != NULL)
		ret = SSL_write(globals.pSSL, message, (int)strlen(message));
	pthread_mutex_unlock(&globals.irc_write_mutex);

	return ret;
}

static int ReadSaslPassword(char *password, size_t password_size) {
	const char *env_pass = getenv("LUNABOT_SASL_PASSWORD");
	if (env_pass == NULL || *env_pass == '\0')
		env_pass = getenv("LUNABOT_NICKSERV_PASSWORD");

	if (env_pass != NULL && *env_pass != '\0') {
		if (strlen(env_pass) >= password_size) {
			Log_fp(LOCAL, "lunabot::ReadSaslPassword() error: SASL password is too long");
			return -1;
		}
		strcpy(password, env_pass);
		return 0;
	}

	FILE *fp = fopen(".passwd", "r");
	if (fp == NULL) {
		snprintf(buffer_log, sizeof(buffer_log),
			"lunabot::ReadSaslPassword() error: Cannot open .passwd: %s",
			strerror(errno));
		Log_fp(LOCAL, buffer_log);
		return -1;
	}

	if (fgets(password, (int)password_size, fp) == NULL) {
		fclose(fp);
		Log_fp(LOCAL, "lunabot::ReadSaslPassword() error: Cannot read .passwd");
		return -1;
	}
	fclose(fp);
	password[strcspn(password, "\r\n")] = '\0';
	if (*password == '\0') {
		Log_fp(LOCAL, "lunabot::ReadSaslPassword() error: SASL password is empty");
		return -1;
	}

	return 0;
}

static int PrepareSaslResponse(struct SaslContext *sasl) {
	char password[BUFFER_SIZE];
	const char *username = getenv("LUNABOT_SASL_USERNAME");
	if (username == NULL || *username == '\0')
		username = globals.nick;

	if (username == NULL || *username == '\0') {
		Log_fp(LOCAL, "lunabot::PrepareSaslResponse() error: SASL username is empty");
		return -1;
	}
	if (ReadSaslPassword(password, sizeof(password)) != 0)
		return -1;

	size_t username_len = strlen(username);
	size_t password_len = strlen(password);
	size_t plain_len = username_len + password_len + 2;
	unsigned char *plain = malloc(plain_len);
	if (plain == NULL) {
		OPENSSL_cleanse(password, sizeof(password));
		Log_fp(LOCAL, "lunabot::PrepareSaslResponse() error: Out of memory");
		return -1;
	}

	plain[0] = '\0';
	memcpy(plain + 1, username, username_len);
	plain[username_len + 1] = '\0';
	memcpy(plain + username_len + 2, password, password_len);

	sasl->response_len = 4 * ((plain_len + 2) / 3);
	sasl->response = malloc(sasl->response_len + 1);
	if (sasl->response == NULL) {
		OPENSSL_cleanse(plain, plain_len);
		free(plain);
		OPENSSL_cleanse(password, sizeof(password));
		Log_fp(LOCAL, "lunabot::PrepareSaslResponse() error: Out of memory");
		return -1;
	}

	EVP_EncodeBlock((unsigned char *)sasl->response, plain, (int)plain_len);
	sasl->response[sasl->response_len] = '\0';
	OPENSSL_cleanse(plain, plain_len);
	free(plain);
	OPENSSL_cleanse(password, sizeof(password));
	return 0;
}

static void FreeSaslResponse(struct SaslContext *sasl) {
	if (sasl->response != NULL) {
		OPENSSL_cleanse(sasl->response, sasl->response_len);
		free(sasl->response);
		sasl->response = NULL;
		sasl->response_len = 0;
	}
}

static int SendSaslResponse(const struct SaslContext *sasl) {
	char message[430];
	size_t offset = 0;

	while (offset < sasl->response_len) {
		size_t chunk_len = sasl->response_len - offset;
		if (chunk_len > 400)
			chunk_len = 400;
		snprintf(message, sizeof(message), "AUTHENTICATE %.*s\r\n",
			(int)chunk_len, sasl->response + offset);
		Log_fp(OUT, "AUTHENTICATE ********");
		if (IrcWrite(message) <= 0)
			return -1;
		offset += chunk_len;
	}

	if (sasl->response_len % 400 == 0) {
		Log_fp(OUT, "AUTHENTICATE +");
		if (IrcWrite("AUTHENTICATE +\r\n") <= 0)
			return -1;
	}

	return 0;
}

static void GetIrcCommand(const char *line, char *command, size_t command_size) {
	const char *p = line;
	if (*p == '@') {
		p = strchr(p, ' ');
		if (p == NULL)
			return;
		p++;
	}
	if (*p == ':') {
		p = strchr(p, ' ');
		if (p == NULL)
			return;
		p++;
	}

	size_t len = strcspn(p, " ");
	if (len >= command_size)
		len = command_size - 1;
	memcpy(command, p, len);
	command[len] = '\0';
}

static int CapabilityListed(const char *line, const char *capability) {
	const char *caps = strstr(line, " :");
	if (caps == NULL)
		return 0;
	caps += 2;

	size_t wanted_len = strlen(capability);
	while (*caps != '\0') {
		size_t token_len = strcspn(caps, " ");
		size_t name_len = strcspn(caps, "= ");
		if (name_len == wanted_len && strncmp(caps, capability, wanted_len) == 0)
			return 1;
		caps += token_len;
		while (*caps == ' ')
			caps++;
	}
	return 0;
}

static int HandleIrcLine(char *line, struct SaslContext *sasl) {
	char command[16] = {0};
	char message[BUFFER_SIZE * 2];

	if (strncmp(line, "PING ", 5) == 0) {
		snprintf(message, sizeof(message), "PONG %s\r\n", line + 5);
		return IrcWrite(message) > 0 ? 0 : -1;
	}

	Log_fp(IN, line);
	GetIrcCommand(line, command, sizeof(command));
	if (strcmp(command, "PONG") == 0 && globals.health_check == 1)
		globals.health_check = 2;

	if (strcmp(command, "CAP") == 0 && strstr(line, " LS ") != NULL &&
	  sasl->state == SASL_WAIT_CAP_LS) {
		if (CapabilityListed(line, "sasl"))
			sasl->sasl_available = 1;
		if (strstr(line, " LS * :") != NULL)
			return 0;
		if (!sasl->sasl_available) {
			Log_fp(LOCAL, "lunabot::SASL error: IRC server does not advertise SASL");
			sasl->state = SASL_FAILED;
			return -1;
		}
		Log_fp(OUT, "CAP REQ :sasl");
		if (IrcWrite("CAP REQ :sasl\r\n") <= 0)
			return -1;
		sasl->state = SASL_WAIT_CAP_ACK;
		return 0;
	}

	if (strcmp(command, "CAP") == 0 && strstr(line, " ACK ") != NULL &&
	  sasl->state == SASL_WAIT_CAP_ACK) {
		if (!CapabilityListed(line, "sasl")) {
			Log_fp(LOCAL, "lunabot::SASL error: IRC server did not acknowledge SASL");
			sasl->state = SASL_FAILED;
			return -1;
		}
		Log_fp(OUT, "AUTHENTICATE PLAIN");
		if (IrcWrite("AUTHENTICATE PLAIN\r\n") <= 0)
			return -1;
		sasl->state = SASL_WAIT_AUTHENTICATE;
		return 0;
	}

	if (strcmp(command, "CAP") == 0 && strstr(line, " NAK ") != NULL) {
		Log_fp(LOCAL, "lunabot::SASL error: IRC server rejected the SASL capability");
		sasl->state = SASL_FAILED;
		return -1;
	}

	if (strcmp(command, "AUTHENTICATE") == 0 && strstr(line, " +") != NULL &&
	  sasl->state == SASL_WAIT_AUTHENTICATE) {
		if (SendSaslResponse(sasl) != 0)
			return -1;
		sasl->state = SASL_WAIT_RESULT;
		return 0;
	}

	if (strcmp(command, "903") == 0 && sasl->state == SASL_WAIT_RESULT) {
		FreeSaslResponse(sasl);
		Log_fp(LOCAL, "SASL authentication successful");
		Log_fp(OUT, "CAP END");
		if (IrcWrite("CAP END\r\n") <= 0)
			return -1;
		sasl->state = SASL_AUTHENTICATED;
		return 0;
	}

	if ((strcmp(command, "902") == 0 || strcmp(command, "904") == 0 ||
	  strcmp(command, "905") == 0 || strcmp(command, "906") == 0 ||
	  strcmp(command, "907") == 0 || strcmp(command, "908") == 0) &&
	  sasl->state != SASL_COMPLETE) {
		snprintf(buffer_log, sizeof(buffer_log),
			"lunabot::SASL error: authentication failed (IRC numeric %s)", command);
		Log_fp(LOCAL, buffer_log);
		sasl->state = SASL_FAILED;
		return -1;
	}

	if (strcmp(command, "001") == 0) {
		if (sasl->state != SASL_AUTHENTICATED) {
			Log_fp(LOCAL, "lunabot::SASL error: IRC registration completed without authentication");
			sasl->state = SASL_FAILED;
			return -1;
		}
		snprintf(message, sizeof(message), "JOIN %s\r\n", globals.channel);
		snprintf(buffer_log, sizeof(buffer_log), "JOIN %s", globals.channel);
		Log_fp(OUT, buffer_log);
		if (IrcWrite(message) <= 0)
			return -1;
		globals.irc_ready = 1;
		sasl->state = SASL_COMPLETE;
	}

	return 0;
}

// IRC connection thread
void *IrcConnect(void *arg) {
	struct sockaddr_in server_addr;
	SSL_CTX *ctx = NULL;
	struct SaslContext sasl = {SASL_WAIT_CAP_LS, 0, NULL, 0};
	char read_buffer[BUFFER_SIZE * 2];
	char line_buffer[BUFFER_SIZE * 4];
	size_t line_len = 0;

	if (PrepareSaslResponse(&sasl) != 0) {
		globals.irc_connected = 0;
		return NULL;
	}

	// Create socket
	globals.irc.irc_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (globals.irc.irc_sock < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: socket() failed: %s",
			strerror(errno));
		Log_fp(LOCAL, buffer_log);
		FreeSaslResponse(&sasl);
		exit(1);
	}

	globals.irc_connected = 1;

	char *ret = GetIP(globals.irc.irc_server_hostname);
	if (ret == NULL) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: Cannot get an IP for '%s'",
			globals.irc.irc_server_hostname);
		Log_fp(LOCAL, buffer_log);
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(globals.irc.irc_server_port);
	server_addr.sin_addr.s_addr = inet_addr(globals.irc.irc_server_ip);

	// Connect to IRC server
	if (connect(globals.irc.irc_sock, (struct sockaddr *)&server_addr,
	  sizeof(server_addr)) < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: connect() failed: %s",
			strerror(errno));
		Log_fp(LOCAL, buffer_log);
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}

	// Setup TLS with the new connection
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	const SSL_METHOD *method = TLS_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		Log_fp(LOCAL, "lunabot::IrcConnect() error: Cannot create SSL context");
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
		Log_fp(LOCAL, "lunabot::IrcConnect() error: Cannot load the TLS trust store");
		SSL_CTX_free(ctx);
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}

	globals.pSSL = SSL_new(ctx);
	if (globals.pSSL == NULL) {
		Log_fp(LOCAL, "lunabot::IrcConnect() error: Cannot create TLS connection");
		SSL_CTX_free(ctx);
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}
	SSL_set_options(globals.pSSL, SSL_OP_NO_COMPRESSION);
	SSL_set_fd(globals.pSSL, globals.irc.irc_sock);
	SSL_set_tlsext_host_name(globals.pSSL, globals.irc.irc_server_hostname);
	SSL_set1_host(globals.pSSL, globals.irc.irc_server_hostname);
	if (SSL_connect(globals.pSSL) != 1) {
		unsigned long ssl_error = ERR_get_error();
		snprintf(buffer_log, sizeof(buffer_log),
			"lunabot::IrcConnect() error: TLS handshake failed: %s",
			ssl_error ? ERR_error_string(ssl_error, NULL) : "unknown TLS error");
		Log_fp(LOCAL, buffer_log);
		SSL_free(globals.pSSL);
		globals.pSSL = NULL;
		SSL_CTX_free(ctx);
		close(globals.irc.irc_sock);
		globals.irc_connected = 0;
		FreeSaslResponse(&sasl);
		return NULL;
	}

	// Start IRCv3 capability negotiation before registration. This keeps the
	// server from completing registration until SASL succeeds and CAP END is sent.
	Log_fp(OUT, "CAP LS 302");
	if (IrcWrite("CAP LS 302\r\n") <= 0)
		goto disconnect;

	snprintf(buffer, sizeof(buffer), "NICK %s\r\n", globals.nick);
	if (IrcWrite(buffer) <= 0)
		goto disconnect;

	snprintf(buffer, sizeof(buffer), "USER %s 0 * :IRC bot for Github webhooks\r\n",
		globals.nick);
	if (IrcWrite(buffer) <= 0)
		goto disconnect;

	// Listen for complete IRC lines. SSL_read() boundaries do not correspond to
	// IRC line boundaries, so retain partial lines and process each CRLF record.
	while (1) {
		int bytes = SSL_read(globals.pSSL, read_buffer, sizeof(read_buffer));
		if (bytes <= 0)
			break;

		for (int i = 0; i < bytes; i++) {
			if (read_buffer[i] == '\n') {
				if (line_len > 0 && line_buffer[line_len - 1] == '\r')
					line_len--;
				line_buffer[line_len] = '\0';
				if (line_len > 0 && HandleIrcLine(line_buffer, &sasl) != 0)
					goto disconnect;
				line_len = 0;
				continue;
			}
			if (line_len >= sizeof(line_buffer) - 1) {
				Log_fp(LOCAL, "lunabot::IrcConnect() error: IRC line is too long");
				goto disconnect;
			}
			line_buffer[line_len++] = read_buffer[i];
		}
	}

	disconnect:
	globals.irc_ready = 0;
	FreeSaslResponse(&sasl);
	pthread_mutex_lock(&globals.irc_write_mutex);
	SSL *ssl = globals.pSSL;
	globals.pSSL = NULL;
	pthread_mutex_unlock(&globals.irc_write_mutex);
	if (ssl != NULL) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	SSL_CTX_free(ctx);
	close(globals.irc.irc_sock);
	globals.irc_connected = 0;
	
	return NULL;
}

void IrcConnectStart(void) {
	pthread_t irc_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&irc_thread, &attr, IrcConnect, NULL);
	pthread_detach(irc_thread);
	pthread_attr_destroy(&attr);
}

// Read user input from the terminal and process per-line
void *ConsoleReadLoop(void *argp) {
	char buffer_line[BUFFER_SIZE];
	while(!globals.mainloopend) {
		memset(buffer_line, 0, BUFFER_SIZE);
		char *ret = fgets(buffer_line, BUFFER_SIZE - 3, stdin);
		if (ret == NULL)
			continue;
		else {
			if (buffer_line[strlen(buffer_line) - 1] == '\n')
				buffer_line[strlen(buffer_line) - 1] = '\0';
		}

		// Don't use strncmp for "quit" since "quit :message here" can be sent
		if (strncmp(buffer_line, "exit", 4) == 0 || strcmp(buffer_line, "quit") == 0 ||
		  strncmp(buffer_line, "qw", 2) == 0) {
			Log_fp(LOCAL, "lunabot exited");
			exit(0);
		}
		else if (strncmp(buffer_line, "reload", 6) == 0) {
			ReloadLibrary();
			
			liblunabotInit_fp();
		}
		else if (strncmp(buffer_line, "replay", 6) == 0) {
			if (strlen(buffer_line) >= 8)
				ReplayJsonPayload_fp(buffer_line + 7);
		}
		else if (strlen(buffer_line) > 0 && *buffer_line != '\n') {
			Log_fp(OUT, buffer_line);
			// Send to server, this is a raw message!
			char buffer2[BUFFER_SIZE * 2];
			memset(buffer2, 0, BUFFER_SIZE * 2);
			sprintf(buffer2, "%s\r\n", buffer_line);
			IrcWrite(buffer2);
		}
	}
	
	return NULL;
}

void ConsoleReadLoopStart(void) {
	pthread_t console_thread;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&console_thread, &attr, ConsoleReadLoop, NULL);
	pthread_detach(console_thread);
	pthread_attr_destroy(&attr);
}

void ParseConfig(void) {
	json_error_t error;
	json_t *root = json_load_file("lunabot.conf.json", 0, &error);
	if (!root) {
		sprintf(buffer, "lunabot::ParseConfig() JSON parsing error: %s", error.text);
		Log_fp(LOCAL, buffer);
		return;
	}
	
	json_t *opt_debug = json_object_get(root, "debug");
	if (opt_debug)
		globals.debug = json_is_true(opt_debug);
	
	json_t *opt_log_filename = json_object_get(root, "log_filename");
	if (opt_log_filename)
		globals.log_filename = strdup(json_string_value(opt_log_filename));
	
	json_t *opt_disable_logging = json_object_get(root, "disable_logging");
	if (opt_disable_logging)
		globals.disable_logging = json_is_true(opt_disable_logging);
	
	json_t *opt_nick = json_object_get(root, "nick");
	if (opt_nick)
		globals.nick = strdup(json_string_value(opt_nick));
	
	json_t *opt_channel = json_object_get(root, "channel");
	if (opt_channel)
		globals.channel = strdup(json_string_value(opt_channel));
	
	json_t *opt_only_core_labels = json_object_get(root, "only_core_labels");
	if (opt_only_core_labels)
		globals.only_core_labels = json_is_true(opt_only_core_labels);

	json_t *opt_ignore_labels = json_object_get(root, "ignore_labels");
	if (opt_ignore_labels)
		globals.ignore_labels = json_is_true(opt_ignore_labels);

	json_t *opt_ignore_pending = json_object_get(root, "ignore_pending");
	if (opt_ignore_pending)
		globals.ignore_pending = json_is_true(opt_ignore_pending);

	json_t *opt_ignore_commits = json_object_get(root, "ignore_commits");
	if (opt_ignore_commits)
		globals.ignore_commits = json_is_true(opt_ignore_commits);

	json_t *opt_webhook_port = json_object_get(root, "webhook_port");
	if (opt_webhook_port)
		globals.webhook_port = (unsigned int)json_integer_value(opt_webhook_port);
	
	json_t *opt_health_check_wait = json_object_get(root, "health_check_wait");
	if (opt_health_check_wait)
		globals.health_check_wait = (unsigned int)json_integer_value(opt_health_check_wait);
	
	json_t *opt_context_name = json_object_get(root, "ci_context_name");
	if (opt_context_name)
		globals.context_name = strdup(json_string_value(opt_context_name));

	json_decref(root);
}

void ParseArgs(int *argc, char **argv) {
	int c;
	while (1) {
		c = getopt_long(*argc, argv, short_options, long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h': // --help
			LunabotHelp();
			exit(0);
			break;
		case 'V': // --version
			printf("lunabot %s\n", lunabot_version_string);
			exit(0);
			break;
		case 'C': // --context
			if (optarg != NULL && strlen(optarg))
				globals.context_name = strdup(optarg);

			break;
		case 'c': // --channel
			if (optarg != NULL && strlen(optarg))
				globals.channel = strdup(optarg);

			break;
		case 'd':
			globals.debug = 1;
			break;
		case 'l': // --log
			if (optarg != NULL && strlen(optarg)) {
				if (strcmp(optarg, "off") == 0)
					globals.disable_logging = 1;
				else
					globals.log_filename = strdup(optarg);
			}

			break;
		case 'n': // --nick
			if (optarg != NULL && strlen(optarg))
				globals.nick = strdup(optarg);

			break;
		case 'p': // --irc-port
			if (optarg != NULL && strlen(optarg))
				globals.irc.irc_server_port = (unsigned int)atoi(optarg);

			break;
		case 's': // --irc-server
			if (optarg != NULL && strlen(optarg))
				globals.irc.irc_server_hostname = strdup(optarg);

			break;
		case 'w': // --webhook-port
			if (optarg != NULL && strlen(optarg))
				globals.webhook_port = (unsigned int)atoi(optarg);

			break;
		default:
			fprintf(stderr, "lunabot::ParseArgs() warning: Unknown "
				"option: %d (%c)\n", c, (char)c);
			break;
		}
	}
}

// Program entry point
int main(int argc, char **argv) {
	ReloadLibrary();
	if (pthread_mutex_init(&globals.irc_write_mutex, NULL) != 0) {
		fprintf(stderr, "lunabot error: Cannot initialize IRC write mutex\n");
		return 1;
	}

	ParseConfig();
	ParseArgs(&argc, argv);

	if (!globals.irc.irc_server_hostname)
		globals.irc.irc_server_hostname = strdup(DEFAULT_IRC_SERVER);

	if (!globals.irc.irc_server_port)
		globals.irc.irc_server_port = DEFAULT_IRC_PORT;
		
	if (!globals.webhook_port)
		globals.webhook_port = DEFAULT_WEBHOOK_PORT;

	if (!globals.nick)
		globals.nick = strdup(DEFAULT_NICK);

	if (!globals.channel)
		globals.channel = strdup(DEFAULT_CHANNEL);

	if (!globals.log_filename)
		globals.log_filename = strdup(DEFAULT_LOG_FILENAME);
	
	if (!globals.health_check_wait)
		globals.health_check_wait = DEFAULT_HEALTH_CHECK_WAIT;

	if (!globals.context_name)
		globals.context_name = strdup(DEFAULT_CONTEXT_NAME);

	ConsoleReadLoopStart();

	liblunabotInit_fp();

	while (!globals.mainloopend) {
		if (!globals.irc_connected) {
			globals.irc_connected = 1;
			IrcConnectStart();
		}
		else
			sleep(5);
	}

	return 0;
}
