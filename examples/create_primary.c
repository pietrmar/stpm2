#include <stdio.h>
#include <string.h>

#include <stpm2.h>

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret;

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		printf("stpm2_init() failed\n");
		return 1;
	}

	ret = stpm2_create_primary(&ctx);
	if (ret < 0) {
		printf("stpm2_create_primary() failed\n");
		return 1;
	}

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		printf("stpm2_free() failed\n");
		return 1;
	}

	return 0;
}
