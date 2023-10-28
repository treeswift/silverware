#include "silver/fork.h"

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    pid_t current = getpid();
    pid_t forked = fork();
    printf("current=%d forked=%d errno=%d\n", current, forked, errno);
}
