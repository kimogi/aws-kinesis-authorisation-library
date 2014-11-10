#include "kinesis_signing.h"

void create_signing_string(List *http_headers, char *payload, char *region, char *longdate, char *shortdate, char **signing_string);
void create_canonical_request(List *headers, char *payload, char **canonical_request);
void create_signing_key(char *secret_key, char *region, char *shortdate, void *signing_key);
void perform_hmac_sha256(char *message, int message_len, char *key, int key_len, void *output, int raw_output);
void get_current_long_date(char **longdate);
void get_current_short_date(char **shortdate);
void get_now_time_struct(struct tm **time_struct);

void create_kinesis_http_headers(char *access_key, char *secret_key, char *region, char *apiversion, char *payload, List **http_headers) {
  char *signed_headers_str = "host;content-type;x-amz-date;x-amz-target;content-length;user-agent;connection";
  char *longdate;
  char *shortdate;
  char signing_key[33];
  char signature[65];

  get_current_short_date(&shortdate);
  get_current_long_date(&longdate);	

  create_signing_key(secret_key, region, shortdate, signing_key);
  if (NULL == signing_key) {
    puts("Failed to create signing");
    return;
  }

  *http_headers = (List *)calloc(1, sizeof(List));

  add_new_item_with_data(*http_headers, "connection:keep-alive", strlen("connection:keep-alive"));

  int content_lenght_header_len = strlen("content-length:") + 10;
  char *content_lenght_header = (char *)calloc(content_lenght_header_len + 1, sizeof(char));
  if (!sprintf(content_lenght_header, "content-length:%d", strlen(payload))) {
    puts("Failed to cretae content_lenght_header");
    free(content_lenght_header);
    return;
  }
  add_new_item_with_data(*http_headers, content_lenght_header, content_lenght_header_len);
  free(content_lenght_header);

  add_new_item_with_data(*http_headers, "content-type:application/x-amz-json-1.1", strlen("content-type:application/x-amz-json-1.1"));

  int host_header_len = strlen("host:kinesis..amazonaws.com") + strlen(region);
  char *host_header = (char *)calloc(host_header_len + 1, sizeof(char));
  if (!sprintf(host_header, "host:kinesis.%s.amazonaws.com", region)) {
    puts("Failed to cretae host_header");
    free(host_header);
    return;
  }
  add_new_item_with_data(*http_headers, host_header, host_header_len);
  free(host_header);

  add_new_item_with_data(*http_headers, "user-agent:LDP", strlen("user-agent:LDP"));

  int amz_date_header_len = strlen("x-amz-date:") + strlen(longdate);
  char *amz_date_header = (char *)calloc(amz_date_header_len + 1, sizeof(char));
  if (!sprintf(amz_date_header, "x-amz-date:%s", longdate)) {
    puts("Failed to cretae amz_date_header");
    free(amz_date_header);
    return;
  }
  add_new_item_with_data(*http_headers, amz_date_header, amz_date_header_len);
  free(amz_date_header);

  int amz_target_header_len = strlen("x-amz-target:Kinesis_.PutRecord") + strlen(apiversion);
  char *amz_target_header = (char *)calloc(amz_target_header_len + 1, sizeof(char));
  if (!sprintf(amz_target_header, "x-amz-target:Kinesis_%s.PutRecord", apiversion)) {
    puts("Failed to cretae amz_target_header");
    free(amz_target_header);
    return;
  }
  add_new_item_with_data(*http_headers, amz_target_header, amz_target_header_len);
  free(amz_target_header);

  char *signing_string = NULL;
  create_signing_string(*http_headers, payload, region, longdate, shortdate, &signing_string);
  perform_hmac_sha256(signing_string, strlen(signing_string), signing_key, 32, signature, 0);
  if (NULL == signature) {
    puts("Failed to create signature");
    free(signing_string);
    return;
  }
  free(signing_string);

  int authorization_header_len =
    strlen("authorization:AWS4-HMAC-SHA256 Credential=//us-east-1/kinesis/aws4_request, SignedHeaders=, Signature=") +
    strlen(access_key) +
    strlen(shortdate) +
    strlen(signed_headers_str) +
    64;

  char *authorization_header = (char *)calloc(authorization_header_len + 1, sizeof(char));
  if (!sprintf(authorization_header, "authorization:AWS4-HMAC-SHA256 Credential=%s/%s/us-east-1/kinesis/aws4_request, SignedHeaders=%s, Signature=%s",
    access_key, shortdate, signed_headers_str, signature)) {

    puts("Failed to create authorization_header");
    free(authorization_header);
    return;
  }
  add_new_item_with_data(*http_headers, authorization_header, authorization_header_len);
  free(authorization_header);
}

void perform_hmac_sha256(char *message, int message_len, char *key, int key_len, void *output, int raw_output) {
  char digest[33];
  memset(digest, 0x00, 33);
  hmac_sha256(message, message_len, key, key_len, digest);
  if (!raw_output) {
    memset(output, 0x00, 65);
    mine_hex_hmac(digest, output);
  } else {
    memset(output, 0x00, 33);
    memcpy(output, digest, 32);
  }
}

void create_signing_key(char *secret_key, char *region, char *shortdate, void *signing_key) {
  char *service = "kinesis";
  char *request = "aws4_request";
  char *k_secret;
  char k_date[33];
  char k_region[33];
  char k_service[33];

  int k_secret_len = strlen("AWS4") + strlen(secret_key);
  k_secret = (char *)calloc(k_secret_len + 1, sizeof(char));
  if (!sprintf(k_secret, "AWS4%s", secret_key)) {
    puts("Failed to create k_secret");
    free(k_secret);
    return;
  }
  perform_hmac_sha256(shortdate, strlen(shortdate), k_secret, k_secret_len, k_date, 1);
  free(k_secret);

  if (NULL == k_date) {
    puts("Failed to create k_date");
    return;
  }
  perform_hmac_sha256(region, strlen(region), k_date, 32, k_region, 1);

  if (NULL == k_region) {
    puts("Failed to create k_region");
    return;
  }
  perform_hmac_sha256(service, strlen(service), k_region, 32, k_service, 1);

  if (NULL == k_service) {
    puts("Failed to create k_service");
    return;
  }
  perform_hmac_sha256(request, strlen(request), k_service, 32, signing_key, 1);
}

void create_signing_string(List *http_headers, char *payload, char *region, char *longdate, char *shortdate, char **signing_string) {
  char *signed_request;
  char *canonical_request_str;

  create_canonical_request(http_headers, payload, &canonical_request_str);

  if (NULL == canonical_request_str) {
    puts("Failed to generate canonical request");
    free(canonical_request_str);
    return;
  }

  hash_sha256(canonical_request_str, strlen(canonical_request_str), &signed_request);
  if (NULL == signed_request) {
    puts("Failed to create signed_request");
    free(signed_request);
    return;
  }
  free(canonical_request_str);

  int signing_string_len = strlen("AWS4-HMAC-SHA256\n\n//kinesis/aws4_request\n") + strlen(longdate) + strlen(shortdate) + strlen(region) + 2*32;
  *signing_string = (char *)calloc(signing_string_len + 1, sizeof(char));
  if (!sprintf(*signing_string, "AWS4-HMAC-SHA256\n%s\n%s/%s/kinesis/aws4_request\n%s", longdate, shortdate, region, signed_request)) {
    puts("Failed to create sign_string");
    free(signing_string);
    return;
  }
}

void create_canonical_request(List *headers, char *payload, char **canonical_request) {
  if (NULL == headers || NULL == payload) {
    puts("Invalid headers or payload list");
    return;
  }       

  char *header_names_line = "connection;content-length;content-type;host;user-agent;x-amz-date;x-amz-target";
  char *hash_payload;

  hash_sha256(payload, strlen(payload), &hash_payload);
  if (NULL == hash_payload) {
    puts("Failed to generate hash payload");
    return;
  }

  List *canonical_request_lines = (List *)calloc(1, sizeof(List));
  add_new_item_with_data(canonical_request_lines, "POST", 4);
  add_new_item_with_data(canonical_request_lines, "/", 1);
  add_new_item_with_data(canonical_request_lines, "", 0);
  listcat(canonical_request_lines, headers);
  add_new_item_with_data(canonical_request_lines, "", 0);
  add_new_item_with_data(canonical_request_lines, header_names_line, strlen(header_names_line));
  add_new_item_with_data(canonical_request_lines, hash_payload, 2*32);    

  *canonical_request = join_all_lines(canonical_request_lines, "\n");  
 
  free_list(canonical_request_lines);
}

void get_now_time_struct(struct tm **time_struct) {
  time_t now;
  putenv("TZ=UTC");
  now = time(NULL);
  *time_struct = localtime(&now);
}

void get_current_long_date(char **longdate) {
  struct tm *time_struct = NULL;
  get_now_time_struct(&time_struct);

  *longdate = (char *)calloc(18, sizeof(char));
  strftime(*longdate, 17, "%Y%m%dT%H%M%SZ", time_struct);
}

void get_current_short_date(char **shortdate) {
  struct tm *time_struct = NULL;
  get_now_time_struct(&time_struct);

  *shortdate = (char *)calloc(10, sizeof(char));
  strftime(*shortdate, 9, "%Y%m%d", time_struct);
}
