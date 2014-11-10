#include <time.h>
#include "crypto_tool.h"
#include "list.h"

void create_kinesis_http_headers(char *access_key, char *secret_key, char *region, char *apiversion, char *payload, List** http_headers);
