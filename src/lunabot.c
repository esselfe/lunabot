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
#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <getopt.h>
#include <microhttpd.h>
#include <jansson.h>

#include "lunabot.h"

const char *lunabot_version_string = "0.5.4";

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
struct RawLine *(*ParseRawLine_fp)(char *line);
void (*FreeRawLine_fp)(struct RawLine *rawp);
void (*SendIrcMessage_fp)(const char *message);
void (*liblunabotInit_fp)(void);

void ReloadLibrary(void) {
	if (handle != NULL)
		dlclose(handle);

	handle = dlopen("./liblunabot.so", RTLD_LAZY);
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
	
	*(void **)(&FreeRawLine_fp) = dlsym(handle, "FreeRawLine");
	if (FreeRawLine_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load FreeRawLine(): %s\n",
			dlerror());
		dlclose(handle);
		exit(1);
	}
	
	*(void **)(&ParseRawLine_fp) = dlsym(handle, "ParseRawLine");
	if (ParseRawLine_fp == NULL) {
		fprintf(stderr,
			"lunabot::ReloadLibrary() error: Cannot load ParseRawLine(): %s\n",
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
			inet_ntop(p->ai_family, addr, globals.irc_server_ip,
				sizeof(globals.irc_server_ip));
			freeaddrinfo(res); // Cleanup
			return globals.irc_server_ip;
		}
		else
			continue;
	}

	freeaddrinfo(res);
	return NULL; // No IP found

}

// IRC connection thread
void *IrcConnect(void *arg) {
	struct sockaddr_in server_addr;

	// Create socket
	globals.irc_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (globals.irc_sock < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: socket() failed: %s",
			strerror(errno));
		Log_fp(LOCAL, buffer_log);
		exit(1);
	}

	globals.irc_connected = 1;

	char *ret = GetIP(globals.irc_server_hostname);
	if (ret == NULL) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: Cannot get an IP for '%s'",
			globals.irc_server_hostname);
		Log_fp(LOCAL, buffer_log);
		close(globals.irc_sock);
		globals.irc_connected = 0;
		return NULL;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(globals.irc_server_port);
	server_addr.sin_addr.s_addr = inet_addr(globals.irc_server_ip);

	// Connect to IRC server
	if (connect(globals.irc_sock, (struct sockaddr *)&server_addr,
	  sizeof(server_addr)) < 0) {
		sprintf(buffer_log, "lunabot::IrcConnect() error: connect() failed: %s",
			strerror(errno));
		Log_fp(LOCAL, buffer_log);
		close(globals.irc_sock);
		globals.irc_connected = 0;
		return NULL;
	}

	// Setup TLS with the new connection
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	const SSL_METHOD *method = TLS_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		Log_fp(LOCAL, "lunabot::IrcConnect() error: Cannot create SSL context");
		close(globals.irc_sock);
		globals.irc_connected = 0;
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

	globals.pSSL = SSL_new(ctx);
	SSL_set_options(globals.pSSL, SSL_OP_NO_COMPRESSION);

	BIO *bio = BIO_new_socket(globals.irc_sock, BIO_CLOSE);
	SSL_set_bio(globals.pSSL, bio, bio);
	SSL_set1_host(globals.pSSL, globals.irc_server_hostname);
	SSL_connect(globals.pSSL);

	// Send basic IRC commands
	sprintf(buffer, "NICK %s\r\n", globals.nick);
	SSL_write(globals.pSSL, buffer, strlen(buffer));

	sprintf(buffer, "USER %s 0 * :IRC bot for Github webhooks\r\n",
		globals.nick);
	SSL_write(globals.pSSL, buffer, strlen(buffer));

	const char *env_pass = getenv("LUNABOT_NICKSERV_PASSWORD");
	if (env_pass != NULL && strlen(env_pass) > 0) {
		sprintf(buffer, "PRIVMSG NickServ :IDENTIFY %s\r\n", env_pass);
		Log_fp(OUT, "PRIVMSG NickServ :IDENTIFY ********");
		SSL_write(globals.pSSL, buffer, strlen(buffer));
	}
	else {
		FILE *fp = fopen(".passwd", "r");
		if (fp == NULL) {
			sprintf(buffer_log, "lunabot::IrcConnect() error: Cannot open .passwd: %s", strerror(errno));
			Log_fp(LOCAL, buffer_log);
			
			globals.irc_connected = 0;
			return NULL;
		}

		char pass[BUFFER_SIZE - 30];
		fgets(pass, BUFFER_SIZE - 31, fp);
		fclose(fp);
		if (pass[strlen(pass)-1] == '\n')
			pass[strlen(pass)-1] = '\0';
		sprintf(buffer, "PRIVMSG NickServ :IDENTIFY %s\r\n", pass);
		Log_fp(OUT, "PRIVMSG NickServ :IDENTIFY ********");
		SSL_write(globals.pSSL, buffer, strlen(buffer));
	}
	
	// Not logged in with NickServ yet, exposes hostmask, you can comment
	// this and send manually in the terminal if you prefer
	sprintf(buffer, "JOIN %s\r\n", globals.channel);
	SSL_write(globals.pSSL, buffer, strlen(buffer));

	// Listen for server messages
	while (1) {
		char buffer2[BUFFER_SIZE*2];
		memset(buffer, 0, BUFFER_SIZE);
		int bytes = SSL_read(globals.pSSL, buffer, BUFFER_SIZE - 1);
		if (bytes <= 0)
			break;

		if (buffer[bytes-1] == '\n')
			buffer[bytes-1] = '\0'; // Remove ending '\n'
		if (buffer[bytes-2] == '\r')
			buffer[bytes-2] = '\0'; // Remove ending '\r'
		
		
		// Respond to ping requests with a pong message
		if (strncmp(buffer, "PING", 4) == 0) {
			sprintf(buffer2, "PONG %s\r\n", buffer + 5);
			SSL_write(globals.pSSL, buffer2, strlen(buffer2));
			continue;
		}
		else
			Log_fp(IN, buffer);
		
		struct RawLine *raw = ParseRawLine_fp(buffer);
		if (raw != NULL) {
			if (strcmp(raw->command, "PONG") == 0)
				Log_fp(LOCAL, "Got a pong from the server!");

			FreeRawLine_fp(raw);
		}
	}

	close(globals.irc_sock);
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
		else if (strlen(buffer_line) > 0 && *buffer_line != '\n') {
			Log_fp(OUT, buffer_line);
			// Send to server, this is a raw message!
			char buffer2[BUFFER_SIZE * 2];
			memset(buffer2, 0, BUFFER_SIZE * 2);
			sprintf(buffer2, "%s\r\n", buffer_line);
			SSL_write(globals.pSSL, buffer2, strlen(buffer2));
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
				globals.irc_server_port = (unsigned int)atoi(optarg);

			break;
		case 's': // --irc-server
			if (optarg != NULL && strlen(optarg))
				globals.irc_server_hostname = strdup(optarg);

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

	ParseConfig();
	ParseArgs(&argc, argv);

	if (!globals.irc_server_hostname)
		globals.irc_server_hostname = strdup(DEFAULT_IRC_SERVER);

	if (!globals.irc_server_port)
		globals.irc_server_port = DEFAULT_IRC_PORT;
		
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

