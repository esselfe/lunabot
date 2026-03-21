#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>

char *SanitizeMessage(json_t *root, json_t *msg) {
	size_t msg_text_len = json_string_length(msg);
	if (msg_text_len < 1) {
		char *str = malloc(7);
		if (str == NULL) {
			fprintf(stderr, "SanitizeMessage() error: malloc() failed!\n");
			exit(1);
			return NULL;
		}
		sprintf(str, "(null)");
		return str;
	}

	char *msg_text = malloc(msg_text_len + 1);
	if (msg_text == NULL) {
		fprintf(stderr, "SanitizeMessage() error: malloc() failed!\n");
		exit(1);
		return NULL;
	}
	memset(msg_text, 0, msg_text_len + 1);

	const char *msg_text_orig = json_string_value(msg);
	const char *c = msg_text_orig;
	unsigned int msg_cnt = 0;
	while (*c != '\0') {
		if (*c == '\n' || *c == '\r' || *c == '\a' || *c == '\033'
		  || *c == '$' || *c == '\\')
			msg_text[msg_cnt] = ' ';
		else
			msg_text[msg_cnt] = msg_text_orig[msg_cnt];

		++c;
		++msg_cnt;
	}

	return msg_text;
}

