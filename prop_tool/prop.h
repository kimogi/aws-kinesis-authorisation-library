#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KINESIS_ACCESS_KEY_PROP "C_KINESIS_ACCESS_KEY"
#define KINESIS_SECRET_KEY_PROP "C_KINESIS_SECRET_KEY"
#define KINESIS_REGION_PROP "C_KINESIS_REGION"
#define KINESIS_STREAM_NAME_PROP "C_KINESIS_STREAM_NAME"
#define KINESIS_API_VERSION_PROP "C_KINESIS_API_VERSION"
#define KINESIS_CONNECTION_TIMEOUT_PROP "C_KINESIS_CONNECTION_TIMEOUT"
#define KINESIS_TIMEOUT_PROP "C_KINESIS_TIMEOUT"

#define KINESIS_ACCESS_KEY_LEN 32
#define KINESIS_SECRET_KEY_LEN 64
#define KINESIS_REGION_LEN 32
#define KINESIS_STREAM_NAME_LEN 128
#define KINESIS_API_VERSION_LEN 8
#define KINESIS_CONNECTION_TIMEOUT_LEN 10
#define KINESIS_TIMEOUT_LEN 10

struct kinesis_props {
	char *access_key;
	char *secret_key;
	char *region;
	char *stream_name;
	char *api_version;
  char *connection_timeout;
  char *timeout;
};

int get_prop(char *file_path, char *prop, char **value, int max_lenght);
