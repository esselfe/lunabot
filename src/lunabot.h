#ifndef LUNABOT_H
#define LUNABOT_H 1

#include <time.h>
#include <openssl/ssl.h>
#include <microhttpd.h>

extern const char *lunabot_version_string;

#define DEFAULT_IRC_SERVER        "irc.libera.chat"
#define DEFAULT_IRC_PORT          6697
#define DEFAULT_NICK              "lunabot"
#define DEFAULT_CHANNEL           "#lunar-lunabot"
#define DEFAULT_WEBHOOK_PORT      3000
#define DEFAULT_LOG_FILENAME      "lunabot.log"
#define DEFAULT_HEALTH_CHECK_WAIT 15

#define BUFFER_SIZE 1024

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

struct GlobalVariables {
	unsigned int debug;
	unsigned int mainloopend;
	int irc_connected;
	int irc_sock;
	char *irc_server_hostname;
	char irc_server_ip[16];
	unsigned int irc_server_port;
	unsigned int webhook_port;
	char *nick;
	char *channel;
	SSL *pSSL;
	struct MHD_Daemon *httpdaemon;
	unsigned int only_core_labels; // Specific to Lunar-Linux
	unsigned int ignore_labels;
	unsigned int ignore_pending;
	unsigned int ignore_commits;
	char *log_filename;
	unsigned int disable_logging;
	int health_check; // Internal
	int health_check_wait;
	time_t health_check_tprev, health_check_t0;
};
extern struct GlobalVariables globals;

struct RawLine {
	char *nick;
	char *username;
	char *host;
	char *command;
	char *channel;
	char *text;
};

#endif /* LUNABOT_H */
