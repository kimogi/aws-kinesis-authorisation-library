#include "kinesis_tool.h"

#define SUCCESS 0
#define FAILURE -1

int perform_http_post(List *http_headers, char *payload, char *dest_url, long connection_timeout, long timeout);
void create_payload(char *stream_name, char *blob, int blob_len, char *partition_key, char **output);
void create_dest_url(char *region, char **output);

int put_record(char *blob, int blob_len, char *partition_key, struct kinesis_props *props) {
	if(NULL == blob || NULL == partition_key || NULL == props) {
		puts("Invalid arguments in put_record");
		return FAILURE;
	}

	char *payload;
  create_payload(props->stream_name, blob, blob_len, partition_key, &payload);
	
	char *dest_url;
	create_dest_url(props->region, &dest_url);
	
	List *http_headers = NULL;
	create_kinesis_http_headers(props->access_key, props->secret_key, props->region, props->api_version, payload, &http_headers);

  long connection_timeout = props->connection_timeout != NULL ? (long)atoi(props->connection_timeout) : 0;
  long timeout = props->timeout != NULL ? (long)atoi(props->timeout) : 0;

  int res = perform_http_post(http_headers, payload, dest_url, connection_timeout, timeout);
	free_list(http_headers);
	return res;
}

void create_payload(char *stream_name, char *blob, int blob_len, char *partition_key, char **output) {
	char *base64_data;
	int base64_data_len;	

	base64_data_len = base64_encode(blob, blob_len, &base64_data);

	*output = (char *)calloc(strlen("{\"StreamName\": \"\",\"Data\": \"\",\"PartitionKey\": \"\"}") + strlen(stream_name) + base64_data_len + strlen(partition_key) + 1, sizeof(char));
	if(!sprintf(*output, "{\"StreamName\": \"%s\",\"Data\": \"%s\",\"PartitionKey\": \"%s\"}", stream_name, base64_data, partition_key)) {
		puts("Failed to create payload");
	}
}

void create_dest_url(char *region, char **output) {
	*output = (char *)calloc(strlen("https://kinesis..amazonaws.com") + strlen(region) + 1, sizeof(char));
	if(!sprintf(*output, "https://kinesis.%s.amazonaws.com", region)) {
		puts("Failed to create destination url string");
	}
}

int perform_http_post(List *http_headers, char *payload, char *dest_url, long connection_timeout, long timeout) {
	CURL *curl;
	CURLcode response;
 
	curl = curl_easy_init();
	if(!curl) {
		puts("Failed to get curl handle");
		return FAILURE;
	}
	
	curl_easy_setopt(curl, CURLOPT_URL, dest_url);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connection_timeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

	struct curl_slist *curl_headers = NULL;
	
	Listitem *node = http_headers->head;
  while (NULL != node) {
    curl_headers = curl_slist_append(curl_headers, node->data);
    node = node->next;
  }
	free(node);
        
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
	response = curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_slist_free_all(curl_headers);
	curl_global_cleanup();

	if(response != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed with code %d : %s\n", response, curl_easy_strerror(response));
		return FAILURE;
	}
	return SUCCESS;
}
