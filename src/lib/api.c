#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <curl/curl.h>

#include "lunabot.h"
#include "liblunabot.h"

static size_t CurlWriteCallback(void *contents, size_t size, size_t nmemb,
  void *userp) {
	size_t realsize = size * nmemb;
	struct CurlBuffer *buf = (struct CurlBuffer *)userp;

	char *ptr = realloc(buf->data, buf->size + realsize + 1);
	if (ptr == NULL) {
		Log(LOCAL, "CurlWriteCallback: realloc failed");
		return 0;
	}

	buf->data = ptr;
	memcpy(&(buf->data[buf->size]), contents, realsize);
	buf->size += realsize;
	buf->data[buf->size] = '\0';

	return realsize;
}

// Fetch a URL from the GitHub API. Returns parsed JSON or NULL on failure.
// Caller must call json_decref() on the returned object.
json_t *FetchGithubApi(const char *url) {
	CURL *curl = curl_easy_init();
	if (curl == NULL) {
		Log(LOCAL, "FetchGithubApi: curl_easy_init failed");
		return NULL;
	}

	struct CurlBuffer response = { .data = malloc(1), .size = 0 };
	if (response.data == NULL) {
		Log(LOCAL, "FetchGithubApi: malloc failed");
		curl_easy_cleanup(curl);
		return NULL;
	}
	response.data[0] = '\0';

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "lunabot");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		char errbuf[BUFFER_SIZE];
		snprintf(errbuf, sizeof(errbuf),
			"FetchGithubApi: curl error for %s: %s",
			url, curl_easy_strerror(res));
		Log(LOCAL, errbuf);
		free(response.data);
		curl_easy_cleanup(curl);
		return NULL;
	}

	curl_easy_cleanup(curl);

	json_t *root;
	json_error_t error;
	root = json_loads(response.data, 0, &error);
	free(response.data);

	if (!root) {
		char errbuf[BUFFER_SIZE];
		snprintf(errbuf, sizeof(errbuf),
			"FetchGithubApi: JSON parse error: %s",
			error.text);
		Log(LOCAL, errbuf);
		return NULL;
	}

	return root;
}

char *FetchPullRequestTitle(const char *repo_full_name, int pr_number) {
	char url[BUFFER_SIZE];
	snprintf(url, sizeof(url),
		"https://api.github.com/repos/%s/pulls/%d",
		repo_full_name, pr_number);

	json_t *root = FetchGithubApi(url);
	if (!root)
		return NULL;

	json_t *title = json_object_get(root, "title");
	if (!json_is_string(title)) {
		Log(LOCAL, "FetchPullRequestTitle: no title field in response");
		json_decref(root);
		return NULL;
	}

	char *title_text = SanitizeMessage(root, title);
	json_decref(root);

	return title_text;
}

// Look up PR number and title by commit SHA using the GitHub API.
// Tries GET /repos/{owner}/{repo}/commits/{sha}/pulls first, then
// falls back to the search API (needed for fork PRs where the
// commits endpoint returns an empty array).
// Sets *out_number and *out_title on success. Caller must free *out_title.
// Returns 0 on success, 1 on failure.
int FetchPullRequestBySha(const char *repo_full_name,
  const char *head_sha, int *out_number, char **out_title) {
	char url[BUFFER_SIZE];
	json_t *root = NULL;
	json_t *pr = NULL;

	// Try commits/{sha}/pulls first (works for non-fork PRs)
	snprintf(url, sizeof(url),
		"https://api.github.com/repos/%s/commits/%s/pulls",
		repo_full_name, head_sha);

	root = FetchGithubApi(url);
	if (root && json_is_array(root) && json_array_size(root) > 0) {
		// Find first PR whose base repo matches (skip fork PRs)
		for (size_t i = 0; i < json_array_size(root); i++) {
			json_t *candidate = json_array_get(root, i);
			json_t *base = json_object_get(candidate, "base");
			json_t *base_repo = json_is_object(base) ?
				json_object_get(base, "repo") : NULL;
			json_t *base_fn = json_is_object(base_repo) ?
				json_object_get(base_repo, "full_name") : NULL;
			if (json_is_string(base_fn) &&
			  strcmp(json_string_value(base_fn), repo_full_name) == 0) {
				pr = candidate;
				break;
			}
		}
	}

	if (pr == NULL) {
		if (root)
			json_decref(root);

		// Fallback: search API (needed for fork PRs)
		snprintf(url, sizeof(url),
			"https://api.github.com/search/issues"
			"?q=repo:%s+type:pr+SHA:%s",
			repo_full_name, head_sha);

		root = FetchGithubApi(url);
		if (!root)
			return 1;

		json_t *items = json_object_get(root, "items");
		if (!json_is_array(items) || json_array_size(items) == 0) {
			Log(LOCAL, "FetchPullRequestBySha: no PRs found for SHA");
			json_decref(root);
			return 1;
		}
		pr = json_array_get(items, 0);
	}

	json_t *number = json_object_get(pr, "number");
	json_t *title = json_object_get(pr, "title");

	if (!json_is_integer(number)) {
		json_decref(root);
		return 1;
	}

	*out_number = json_integer_value(number);
	*out_title = NULL;

	if (json_is_string(title))
		*out_title = SanitizeMessage(root, title);

	json_decref(root);
	return 0;
}

