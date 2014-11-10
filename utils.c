#include "kinesis/kinesis_tool.h"
#include <stdarg.h>

#define PUT_RECORD_KEY "put_record"
#define NAME_KEY "-name"
#define BLOB_KEY "-b"
#define CONFIG_KEY "-c"
#define PARTITION_KEY_KEY "-pk"

#define SUCCESS 0
#define FAILURE -1
#define DEFAULT_PROP_FILE "/etc/blix/config"

void handle_put_record(char **args, char *prop_file_path);
int mine_blob(char *file_path, char **blob);
void print_help();
void print_usage_error(const char *format, ...);
int gain_kinesis_props(char *prop_file_path, struct kinesis_props **props);
void free_kinesis_props(struct kinesis_props *props);

int main(int argc, char **argv) {
  if (1 >= argc) {
    print_usage_error("Unexpected number of arguments");
    return EXIT_SUCCESS;
  }

  char *prop_file_path = DEFAULT_PROP_FILE;
  int c_argc = argc - 1;
  char **c_argv = argv + 1;

  if (3 <= argc && 0 == strcmp(*(argv + 1), CONFIG_KEY)) {
    prop_file_path = *(argv +  2);
    c_argc -= 2;
    c_argv += 2;
  }

  if (2 <= c_argc && 0 == strcmp(*c_argv, NAME_KEY)) {
    if (0 == strcmp(*(c_argv + 1), PUT_RECORD_KEY)) {
      c_argc -= 2; 		
      c_argv += 2;		

      if (4 == c_argc)
        handle_put_record(c_argv, prop_file_path);
      else
        print_usage_error("Unexpected number of arguments");	

    } else {
      print_usage_error("Unexpected operation specified : %s", *(c_argv + 1));
    }

  } else {
    print_usage_error("No operation specified");
  }

  return EXIT_SUCCESS;
}

void handle_put_record(char **argv, char *prop_file_path) {
  struct kinesis_props *props = NULL;

  if (FAILURE == gain_kinesis_props(prop_file_path, &props)) {
    puts("Failed to load kinesis props");
    return;
  }

  if (0 != strcmp(*argv, BLOB_KEY) || 0 != strcmp(*(argv + 2), PARTITION_KEY_KEY)) {
    print_usage_error("Unexpected arguments for specified operation");
    return;
  }

  char *blob_file_path = *(argv + 1);
  char *part_key = *(argv + 3);

  char *blob;
  int blob_len;

  blob_len = mine_blob(blob_file_path, &blob);
  if (NULL == blob) {
    printf("Failed to mine blob from file %s\n", blob_file_path);
    return;
  }

  put_record(blob, blob_len, part_key, props);
  free_kinesis_props(props);
}

int mine_blob(char *file_path, char **blob) {
  FILE *file = fopen(file_path, "r");
  int byte_read = 0;
  int block_size = 40*1024;
  char block_buf[block_size];

  byte_read = fread(block_buf, sizeof(char), block_size, file);
  if (0 > byte_read) {
    printf("Failed to read bites from file %s\n", file_path);
    return -1;
  }

  *blob = (char *)calloc(byte_read + 1, sizeof(char));
  memcpy(*blob, block_buf, byte_read);

  fclose(file);
  return byte_read;
}

void print_usage_error(const char *format, ...) {
  va_list arg;

  va_start(arg, format);
  puts("ERROR : ");
  vfprintf(stdout, format, arg);
  va_end (arg);
  puts("\n");

  print_help();
}

void print_help() {
  printf("\nUsage :\n	utils [-c path to config file] -name <operation name> <operation args>\n");
  printf("Operations :\n\n	name : put_record\n	args : -b <path to blob file> -pk <partition key>\n");
  printf("\nMore info about partition key : http://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecord.html#Kinesis-PutRecord-request-PartitionKey\n\n");
}

int gain_kinesis_props(char *prop_file_path, struct kinesis_props **props) {
  *props = (struct kinesis_props *)calloc(1, sizeof(struct kinesis_props));

  int res;

  if (FAILURE == (res = get_prop(prop_file_path, KINESIS_STREAM_NAME_PROP, &((*props)->stream_name), KINESIS_STREAM_NAME_LEN))) {
    printf("No such property found : %s\n", KINESIS_STREAM_NAME_PROP);
  }
  if (FAILURE == (res = get_prop(prop_file_path, KINESIS_API_VERSION_PROP, &((*props)->api_version), KINESIS_API_VERSION_LEN))) {
    printf("No such property found : %s\n", KINESIS_API_VERSION_PROP);
  }
  if (FAILURE == (res = get_prop(prop_file_path, KINESIS_ACCESS_KEY_PROP, &((*props)->access_key), KINESIS_ACCESS_KEY_LEN))) {
    printf("No such property found : %s\n", KINESIS_ACCESS_KEY_PROP);
  }
  if (FAILURE == (res = get_prop(prop_file_path, KINESIS_SECRET_KEY_PROP, &((*props)->secret_key), KINESIS_SECRET_KEY_LEN))) {
    printf("No such property found : %s\n", KINESIS_SECRET_KEY_PROP);
  }
  if (FAILURE == (res = get_prop(prop_file_path, KINESIS_REGION_PROP, &((*props)->region), KINESIS_REGION_LEN))) {
    printf("No such property found : %s\n", KINESIS_REGION_PROP);
  }

  get_prop(prop_file_path, KINESIS_CONNECTION_TIMEOUT_PROP, &((*props)->connection_timeout), KINESIS_CONNECTION_TIMEOUT_LEN);
  get_prop(prop_file_path, KINESIS_TIMEOUT_PROP, &((*props)->timeout), KINESIS_TIMEOUT_LEN);

  if (FAILURE == res) {
    free_kinesis_props(*props);
  }
  return res;
}

void free_kinesis_props(struct kinesis_props *props) {
  if (NULL != props) {
    if (NULL != props->access_key)
      free(props->access_key);
    if (NULL != props->secret_key)
      free(props->secret_key);
    if (NULL != props->stream_name)
      free(props->stream_name);
    if (NULL != props->region)
      free(props->region);
    if (NULL != props->api_version)
      free(props->api_version);
    if (NULL != props->connection_timeout)
      free(props->connection_timeout);
    if (NULL != props->timeout)
      free(props->timeout);
    free(props);
  }
}
