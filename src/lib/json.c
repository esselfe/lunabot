#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <jansson.h>

#include "lunabot.h"
#include "liblunabot.h"

// Check whether a label event should be skipped based on config flags
// and repository name. Returns 1 to skip, 0 to process.
static int ShouldSkipLabelEvent(json_t *root) {
	if (libglobals->ignore_labels)
		return 1;

	if (libglobals->only_core_labels) {
		json_t *repo = json_object_get(root, "repository");
		json_t *repo_name = json_is_object(repo) ?
			json_object_get(repo, "name") : NULL;
		if (json_is_string(repo_name) &&
		  strcmp(json_string_value(repo_name), "moonbase-core") != 0)
			return 1;
	}

	return 0;
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
		if (strcmp(json_string_value(context), libglobals->context_name) != 0) {
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
		char *msg_text = SanitizeMessage(root, msg);
		char *msg_text_limited = malloc(128);
		if (msg_text_limited == NULL) {
			sprintf(buffer, "JSON parsing error: malloc() returned NULL!");
			Log(LOCAL, buffer);
			return;
		}
		snprintf(msg_text_limited, 128, "%s", msg_text);

		char *color = YELLOW;
		char *status_str = strdup(json_string_value(status));
		if (strcmp(status_str, "pending") == 0) {
			// Reduce message volume and skip those
			if (libglobals->ignore_pending) {
				free(msg_text);
				free(msg_text_limited);
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
		else if (strcmp(status_str, "failure") == 0 ||
			 strcmp(status_str, "error") == 0) {
			snprintf(buffer, sizeof(buffer),
				"[%sFailed%s]:    '%s' %s",
				RED, NORMAL,
				msg_text_limited,
				json_string_value(target_url));
			SendIrcMessage(buffer);
			free(msg_text);
			free(msg_text_limited);
			free(status_str);

			json_decref(root);
			return;
		}

		snprintf(buffer, sizeof(buffer),
			"[%s%s%s]:   '%s' %s",
			color, status_str, NORMAL,
			msg_text_limited, 
			json_string_value(target_url));
		SendIrcMessage(buffer);
		
		free(msg_text);
		free(msg_text_limited);
		free(status_str);
		json_decref(root);
		return;
	}
	
	// Process PR ops
	json_t *action = json_object_get(root, "action");
	json_t *pr = json_object_get(root, "pull_request");
	if (json_is_string(action) && json_is_object(pr)) {
		if (strcmp(json_string_value(action), "labeled") == 0) {
			if (ShouldSkipLabelEvent(root)) {
				json_decref(root);
				return;
			}

			json_t *sender = json_object_get(root, "sender");
			if (!json_is_object(sender)) {
				json_decref(root);
				return;
			}
			json_t *username = json_object_get(sender, "login");
			json_t *title = json_object_get(pr, "title");
			if (!json_is_string(title)) {
				json_decref(root);
				return;
			}
			char *title_text = SanitizeMessage(root, title);

			json_t *url = json_object_get(pr, "html_url");
			json_t *label = json_object_get(root, "label");
			json_t *label_name = json_object_get(label, "name");
			snprintf(buffer, sizeof(buffer),
				"[%sLabels%s]:    %s added the '%s' label to '%s' - %s",
				LIGHT_GREEN, NORMAL,
				json_string_value(username),
				json_string_value(label_name),
				title_text,
				json_string_value(url));
			SendIrcMessage(buffer);
			free(title_text);
			json_decref(root);
			return;
		}
		else if (strcmp(json_string_value(action), "unlabeled") == 0) {
			if (ShouldSkipLabelEvent(root)) {
				json_decref(root);
				return;
			}

			json_t *sender = json_object_get(root, "sender");
			if (!json_is_object(sender)) {
				json_decref(root);
				return;
			}
			json_t *username = json_object_get(sender, "login");
			json_t *title = json_object_get(pr, "title");
			if (!json_is_string(title)) {
				json_decref(root);
				return;
			}
			char *title_text = SanitizeMessage(root, title);

			json_t *url = json_object_get(pr, "html_url");
			json_t *label = json_object_get(root, "label");
			json_t *label_name = json_object_get(label, "name");
			snprintf(buffer, sizeof(buffer),
				"[%sLabels%s]:    %s removed the '%s' label to '%s' - %s",
				LIGHT_GREEN, NORMAL,
				json_string_value(username),
				json_string_value(label_name),
				title_text,
				json_string_value(url));
			SendIrcMessage(buffer);
			free(title_text);
			json_decref(root);
			return;
		}
		else if (strcmp(json_string_value(action), "opened") == 0) {
			json_t *title = json_object_get(pr, "title");
			if (!json_is_string(title)) {
				json_decref(root);
				return;
			}
			char *title_text = SanitizeMessage(root, title);

			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");

			if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
				snprintf(buffer, sizeof(buffer), 
					"[%sNew PR%s]:    '%s' from %s - %s",
					GREEN, NORMAL,
					title_text, 
					json_string_value(user), 
					json_string_value(url));
				SendIrcMessage(buffer);
				free(title_text);
				json_decref(root);
				return;
			}
		}
		else if (strcmp(json_string_value(action), "closed") == 0) {
			json_t *title = json_object_get(pr, "title");
			if (!json_is_string(title)) {
				json_decref(root);
				return;
			}
			char *title_text = SanitizeMessage(root, title);

			json_t *user = json_object_get(json_object_get(pr, "user"), "login");
			json_t *url = json_object_get(pr, "html_url");
			json_t *is_merged = json_object_get(pr, "merged");
			if (is_merged != NULL && json_is_true(is_merged)) {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					snprintf(buffer, sizeof(buffer),
						"[%sMerged PR%s]: '%s' from %s - %s",
						CYAN, NORMAL,
						title_text,
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(buffer);
					free(title_text);
					json_decref(root);
					return;
				}
			}
			else {
				if (json_is_string(title) && json_is_string(user) && json_is_string(url)) {
					snprintf(buffer, sizeof(buffer),
						"[%sClosed PR%s]: '%s' from %s - %s",
						RED, NORMAL,
						title_text,
						json_string_value(user),
						json_string_value(url));
					SendIrcMessage(buffer);
					free(title_text);
					json_decref(root);
					return;
				}
			}
		}
	}
	
	// Process check runs
	json_t *check = json_object_get(root, "check_run");
	if (check != NULL) {
		json_t *name = json_object_get(check, "name");
		if (!json_is_string(name)) {
			json_decref(root);
			return;
		}

		// Only handle "lint" check runs
		if (strcmp(json_string_value(name), "lint") != 0) {
			json_decref(root);
			return;
		}

		json_t *check_status = json_object_get(check, "status");
		if (!json_is_string(check_status) ||
		  strcmp(json_string_value(check_status), "completed") != 0) {
			json_decref(root);
			return;
		}

		json_t *check_conclusion = json_object_get(check, "conclusion");
		if (!json_is_string(check_conclusion)) {
			json_decref(root);
			return;
		}

		const char *conclusion = json_string_value(check_conclusion);
		json_t *html_url = json_object_get(check, "html_url");

		// Get repo full name from repository.full_name
		const char *repo_full_name = NULL;
		json_t *repo = json_object_get(root, "repository");
		if (json_is_object(repo)) {
			json_t *fn = json_object_get(repo, "full_name");
			if (json_is_string(fn))
				repo_full_name = json_string_value(fn);
		}

		// Extract PR number from check_run.pull_requests[0].number,
		// but only if the PR's base repo matches the event's repository.
		// GitHub includes fork PRs in this array (e.g. a fork's sync PR
		// tracking upstream master), which produces false associations.
		int pr_number = 0;
		json_t *prs = json_object_get(check, "pull_requests");
		if (json_is_array(prs) && json_array_size(prs) > 0) {
			json_t *pr_obj = json_array_get(prs, 0);
			json_t *pr_base = json_object_get(pr_obj, "base");
			json_t *pr_base_repo = json_is_object(pr_base) ?
				json_object_get(pr_base, "repo") : NULL;
			json_t *pr_base_repo_id = json_is_object(pr_base_repo) ?
				json_object_get(pr_base_repo, "id") : NULL;
			json_t *event_repo_id = json_is_object(repo) ?
				json_object_get(repo, "id") : NULL;

			if (json_is_integer(pr_base_repo_id) &&
			  json_is_integer(event_repo_id) &&
			  json_integer_value(pr_base_repo_id) ==
			  json_integer_value(event_repo_id)) {
				json_t *pr_num = json_object_get(pr_obj, "number");
				if (json_is_integer(pr_num))
					pr_number = json_integer_value(pr_num);
			}
		}

		// Fetch PR title from GitHub API (may return NULL)
		char *pr_title = NULL;

		// If pull_requests[] is empty (common with fork PRs),
		// look up the PR by commit SHA via the GitHub API
		if (pr_number == 0 && repo_full_name != NULL) {
			json_t *head_sha = json_object_get(check, "head_sha");
			if (json_is_string(head_sha)) {
				FetchPullRequestBySha(repo_full_name,
					json_string_value(head_sha),
					&pr_number, &pr_title);
			}
		}

		if (pr_number > 0 && pr_title == NULL && repo_full_name != NULL)
			pr_title = FetchPullRequestTitle(repo_full_name, pr_number);

		if (strcmp(conclusion, "failure") == 0) {
			if (pr_number > 0 && repo_full_name != NULL) {
				snprintf(buffer, sizeof(buffer),
					"[%sChecks%s]:    lint failed for PR #%d '%s' - "
					"https://github.com/%s/pull/%d | %s",
					RED, NORMAL,
					pr_number,
					pr_title ? pr_title : "(unknown)",
					repo_full_name, pr_number,
					json_is_string(html_url) ?
						json_string_value(html_url) : "");
			} else {
				snprintf(buffer, sizeof(buffer),
					"[%sChecks%s]:    lint failed - %s",
					RED, NORMAL,
					json_is_string(html_url) ?
						json_string_value(html_url) : "");
			}
			SendIrcMessage(buffer);
		}
		else if (strcmp(conclusion, "success") == 0) {
			if (pr_number > 0 && repo_full_name != NULL) {
				snprintf(buffer, sizeof(buffer),
					"[%sChecks%s]:    lint passed for PR #%d '%s' - "
					"https://github.com/%s/pull/%d",
					GREEN, NORMAL,
					pr_number,
					pr_title ? pr_title : "(unknown)",
					repo_full_name, pr_number);
			} else {
				snprintf(buffer, sizeof(buffer),
					"[%sChecks%s]:    lint passed",
					GREEN, NORMAL);
			}
			SendIrcMessage(buffer);
		}

		free(pr_title);
		json_decref(root);
		return;
	}
	
	// Process push commits
	json_t *ref = json_object_get(root, "refs");
	json_t *commits = json_object_get(root, "commits");
	json_t *committer = NULL;
	json_t *username = NULL;
	json_t *msg = NULL;
	json_t *url = NULL;
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
			
			if (username != NULL && json_is_string(username) && json_is_string(msg) &&
			  json_is_string(url)) {
				char *msg_text = SanitizeMessage(root, msg);

				snprintf(buffer, sizeof(buffer),
					"[%sCommits%s]:   '%s' from %s - %s",
					CYAN, NORMAL,
					msg_text,
					json_string_value(username),
					json_string_value(url));
				SendIrcMessage(buffer);
				
				free(msg_text);
				json_decref(root);
				return;
			}
		}
	}

	Log(LOCAL, "Got webhook data without a conditional branch for it!");

	json_decref(root);
}

void ReplayJsonPayload(char *filename) {
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		char buffer_tmp[1024];
		sprintf(buffer_tmp, "ReplayJsonPayload() error: cannot open '%s': %s",
			filename, strerror(errno));
		Log(LOCAL, buffer_tmp);
		return;
	}
	
	fseek(fp, 0, SEEK_END);
	unsigned long filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	char *payload = malloc(filesize + 1);
	memset(payload, 0, filesize + 1);
	if (payload == NULL) {
		Log(LOCAL, "ReplayJsonPayload() error: cannot allocate memory!");
		fclose(fp);
		return;
	}
	
	int ret = fread(payload, filesize, 1, fp);
	if (ret > 0)
		ParseJsonData(payload);
	
	free(payload);
	fclose(fp);
}

