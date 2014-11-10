#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <math.h>

void printdump(const char *buffer, size_t sz);
void mine_hex_hmac(const char *digest, void *output);
void hmac_sha256(const unsigned char *text, int text_len, const unsigned char *key, int key_len, void *digest);
void hash_sha256(char *message, int message_len, char **output);
int base64_encode(const char *message, int message_len, char **output);
