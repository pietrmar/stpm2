#include <stdio.h>

#include <stpm2.h>

int main(int argc, char *argv[])
{
	uint8_t random_byte;

	stpm2_get_random(NULL, &random_byte, 1);

	printf("0x%02x\n", random_byte);

	return 0;
}
