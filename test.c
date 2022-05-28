#include <stdio.h>
#include <string.h>
#include "a.h"

int main() {
	// genkey
	struct buffer buf  = genkey_from_osrng();
   printf("%ld\n", buf.len);
   int i;
	for (i = 0; i < buf.len; i++) {
    	if (i > 0) printf(":");
    	printf("%02X", buf.data[i]);
	}

   printf("\n\n");
	struct buffer msg;
	uint8_t raw_msg[512] = {0};
	memcpy(raw_msg, "hello world", sizeof("hello world"));
	msg.data = raw_msg;
	msg.len = strlen(raw_msg);

	// sign
	struct buffer signature = sign(buf, msg);
	for (i = 0; i < signature.len; i++) {
    	if (i > 0) printf(":");
    	printf("%02X", signature.data[i]);
	}

	// verify
	uint8_t raw_pub_key[32] = {0};
	memcpy(raw_pub_key, &buf.data[32],32);

	struct buffer pub_key;
	pub_key.data = raw_pub_key;
	pub_key.len = 32;

	bool ok = verify(pub_key, msg, signature);

	printf("\n\n");
	if(ok){
		printf("ok");
	}else{
		printf("not ok");
	}

	struct buffer msg_fake;
	uint8_t raw_msg_fake[512] = {0};
	memcpy(raw_msg_fake, "fake hello world", sizeof("fake hello world"));
	msg_fake.data = raw_msg_fake;
	msg_fake.len = strlen(raw_msg_fake);

	ok = verify(pub_key, msg_fake, signature);

	printf("\n\n");
	if(ok){
		printf("ok");
	}else{
		printf("not ok");
	}
	printf("\n\n");

}
