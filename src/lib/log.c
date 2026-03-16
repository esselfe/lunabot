#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "lunabot.h"
#include "liblunabot.h"

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
	struct tm *tm0 = (struct tm *)malloc(sizeof(struct tm));
	gmtime_r(&t0, tm0);
	struct timeval tv0;
	gettimeofday(&tv0, NULL);

	// Show message in console with colors
	fprintf(stdout, "\033[00;36m%04d%02d%02d-%02d:%02d:%02d.%06ld %s"
		"##\033[00m%s\033[00;36m##\033[00m\n", 
		tm0->tm_year+1900, tm0->tm_mon+1, tm0->tm_mday,
		tm0->tm_hour, tm0->tm_min, tm0->tm_sec, tv0.tv_usec,
		dirstr, text);

	if (libglobals->disable_logging) {
		free(tm0);
		return;
	}

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

	free(tm0);
	fclose(log_fp);
}

