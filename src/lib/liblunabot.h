#ifndef LIBLUNABOT_H
#define LIBLUNABOT_H 1

#include <microhttpd.h>
#include <jansson.h>

#include "lunabot.h"

extern struct GlobalVariables *libglobals;

// From src/lib/api.c

struct CurlBuffer {
	char *data;
	size_t size;
};

json_t *FetchGithubApi(const char *url);
char *FetchPullRequestTitle(const char *repo_full_name, int pr_number);
int FetchPullRequestBySha(const char *repo_full_name,
	const char *head_sha, int *out_number, char **out_title);

// From src/lib/health-check.c
enum MHD_Result HandleHealthCheck(struct MHD_Connection *connection);

// From src/lib/irc.c
void SendIrcMessage(const char *message);

// From src/lib/json.c
void ParseJsonData(char *json_data);
void ReplayJsonPayload(char *filename);

// From src/lib/log.c
void Log(unsigned int direction, char *text);

// From src/lib/sanitize.c
char *SanitizeMessage(json_t *root, json_t *msg);

// From src/lib/verify-signature.c
int VerifySignature_func(const char *payload, const char *signature);
#endif /* LIBLUNABOT_H */
