/*
 * Use-After-Free test case for CodeQL.
 *
 * 包含三种漏洞模式 + 安全对照组：
 *   1. vulnerable_uaf       - 经典：free 之后继续读写堆指针
 *   2. uaf_after_realloc    - realloc 失败后访问旧指针
 *   3. dangling_in_loop     - 循环中先 free 再使用
 *   4. safe_*               - 安全写法（对照组，不应被告警）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 漏洞 1：free 后直接 use */
void vulnerable_uaf(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "hello world");
    free(buf);
    printf("after free: %s\n", buf);   /* UAF: read after free */
    buf[0] = 'H';                       /* UAF: write after free */
}

/* 漏洞 2：realloc 失败后旧指针其实未被释放，但若 realloc 成功则旧 ptr 已失效 */
void uaf_after_realloc(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    char *q = (char *)realloc(p, 1024);
    if (q == NULL) {
        /* realloc 失败：p 还有效，可以继续用，这里 OK */
        free(p);
        return;
    }
    /* realloc 成功：p 现在是悬空指针 */
    strcpy(p, "boom");                  /* UAF: p 已被 realloc 释放 */
    free(q);
}

/* 漏洞 3：循环中先 free 再使用 */
void dangling_in_loop(int n) {
    char *p = (char *)malloc(16);
    if (!p) return;
    for (int i = 0; i < n; i++) {
        if (i == 2) {
            free(p);
        }
        p[i % 16] = (char)('a' + i);   /* 当 i>=3 时为 UAF */
    }
}

/* 对照组：free 后置空，下次使用前检查 */
void safe_free_then_null(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "ok");
    free(buf);
    buf = NULL;
    if (buf) {
        printf("%s\n", buf);            /* 不会执行 */
    }
}

int main(void) {
    vulnerable_uaf();
    uaf_after_realloc();
    dangling_in_loop(5);
    safe_free_then_null();
    return 0;
}
