#include "crypto_tool.h"

#define NUL '\0'

char *sha256_hash_string(char hash[SHA256_DIGEST_LENGTH]);
/**
	text - pointer to data stream;
	text_len - length of data stream;
	key - pointer to authentication key;
	key_len - length of authentication key;
	digest - caller digest to be filled in;
	raw_output - binary output when 1 set, lowercase hexits when 0
*/

void hmac_sha256(const unsigned char *text, int text_len, const unsigned char *key, int key_len, void *digest) {
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[SHA256_DIGEST_LENGTH];
	unsigned char tk2[SHA256_DIGEST_LENGTH];
	unsigned char bufferIn[1024];
	unsigned char bufferOut[1024];
	int i;
    
	/* if key is longer than 64 bytes reset it to key=sha256(key) */
	if(key_len > 64) {
		SHA256( key, key_len, tk );
		key = tk;
		key_len = SHA256_DIGEST_LENGTH;
	}

	/*
	* the HMAC_SHA256 transform looks like:
	*
	* SHA256(K XOR opad, SHA256(K XOR ipad, text))
	*
    	* where K is an n byte key
    	* ipad is the byte 0x36 repeated 64 times
    	* opad is the byte 0x5c repeated 64 times
    	* and text is the data being protected
    	*/

   	/* start out by storing key in pads */
   	memset(k_ipad, 0, sizeof k_ipad);
   	memset(k_opad, 0, sizeof k_opad);
   	memcpy(k_ipad, key, key_len);
   	memcpy(k_opad, key, key_len);
    
   	/* XOR key with ipad and opad values */
   	for (i=0; i<64; i++) {
   		k_ipad[i] ^= 0x36;
   		k_opad[i] ^= 0x5c;
   	}

   	/*
   	* perform inner SHA256
   	*/
   	memset(bufferIn, 0x00, 1024);
   	memcpy(bufferIn, k_ipad, 64);
   	memcpy(bufferIn + 64, text, text_len);
    
   	SHA256(bufferIn, 64 + text_len, tk2);

   	/*
   	* perform outer SHA256
   	*/
   	memset(bufferOut, 0x00, 1024);
   	memcpy(bufferOut, k_opad, 64);
   	memcpy(bufferOut + 64, tk2, SHA256_DIGEST_LENGTH);
    
   	SHA256(bufferOut, 64 + SHA256_DIGEST_LENGTH, digest);
}

void mine_hex_hmac(const char *digest, void *output) {
	if(NULL == digest) {
		fprintf(stderr, "Error: failed to mine hmac, null pointer passed\n");
		return;
	}		

	int  i, c;
	char chunk_str[3];
	
	char temp[2*SHA256_DIGEST_LENGTH];
	if(NULL == output)
		output = temp;		
  	
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if(!sprintf(chunk_str, "%02x", digest[i] & 0xFF)) {
			puts("Error: failed to mine hmac, invalid digest format");
			return;
		}
		strcat(output, chunk_str);
	}
}

void hash_sha256(char *message, int message_len, char **output) {
	if(NULL == message || 0 >= message_len)
		return;
	
	char hash[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256;
    	SHA256_Init(&sha256);
        SHA256_Update(&sha256, message, message_len);
    	SHA256_Final(hash, &sha256);
	*output = sha256_hash_string(hash);
}

char *sha256_hash_string(char hash[]) {
	char *hash_str = (unsigned char *)calloc(65, sizeof(char)); 
	char chunk[3];	
	
	int i;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if(!sprintf(chunk, "%02x", (unsigned char)hash[i])) {
			puts("Error: failed to convert hash to string");
                        free(hash_str);
                        return NULL;
		}
		strcat(hash_str, chunk);
	}
	return hash_str;
}

void printdump(const char *buffer, size_t sz) {
	int i, c;
	unsigned char   buf[80];
 
	for(i = 0; (unsigned)i < sz; i++) {
        	if ( (i != 0) && (i % 16 == 0) ) {
            		buf[16] = NUL;
            		fprintf( stderr, "    %s\n", buf );
        	}
        	if ( i % 16 == 0 )
            		fprintf( stderr, "%08x:", &buffer[i] );
        	c = buffer[i] & 0xFF;
        	if ( (c >= ' ') && (c <= 0x7E) )
            		buf[i % 16] = (unsigned char)c;
        	else
            		buf[i % 16] = '.';
        	fprintf( stderr, " %02x", c & 0xFF );
    	}
    	if ( i % 16 == 0 )
        	buf[16] = NUL;
    	else {
        	buf[i % 16] = NUL;
        	for ( i = i % 16; i < 16; i++ )
           		fputs( "   ", stderr );
    	}
	fprintf( stderr, "    %s\n", buf );
}

int base64_encode(const char *message, int message_len, char **output) {
	BIO *bio, *b64;
	FILE* stream;
	int encoded_size = 4 * ceil((double)message_len / 3);
	*output = (char *)malloc(encoded_size + 1);
 
	stream = (FILE *)fmemopen(*output, encoded_size + 1, "w");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, message, message_len);
	BIO_flush(bio);
	BIO_free_all(bio);
	fclose(stream);
	return encoded_size;
}
