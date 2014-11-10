#include <curl/curl.h>
#include "kinesis_signing.h"
#include "../prop_tool/prop.h"

int put_record(char *blob, int blob_len, char *partition_key, struct kinesis_props *props);
