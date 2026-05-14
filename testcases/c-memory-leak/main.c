/*
 * Memory / Resource Leak test case for CodeQL.
 *
 * 包含五种漏洞模式 + 安全对照组：
 *   1. simple_leak       - 分配后从未释放
 *   2. leak_on_error     - 错误分支提前 return 导致泄漏
 *   3. leak_overwrite    - 旧指针未释放，被新分配的指针覆盖
 *   4. leak_in_loop      - 循环内多次分配但只释放一次
 *   5. file_handle_leak  - fopen 后未 fclose（资源泄漏）
 *   6. safe_*            - 安全写法
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 漏洞 1：最经典的 malloc 后未 free */
void simple_leak(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return;
    strcpy(buf, "this buffer is never freed");
    /* 缺少 free(buf) */
}

/* 漏洞 2：错误路径提前 return，未释放已分配资源 */
int leak_on_error(int n) {
    int *arr = (int *)malloc(sizeof(int) * 100);
    if (!arr) return -1;

    if (n < 0) {
        return -1;              /* leak: arr 未释放 */
    }
    if (n > 1000) {
        return -2;              /* leak: arr 未释放 */
    }

    for (int i = 0; i < n; i++) {
        arr[i] = i;
    }
    free(arr);
    return 0;
}

/* 漏洞 3：指针被新分配的内存覆盖，旧的丢失 */
void leak_overwrite(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    strcpy(p, "first");
    p = (char *)malloc(128);    /* leak: 第一次分配的 64 字节内存被泄漏 */
    if (!p) return;
    strcpy(p, "second");
    free(p);
}

/* 漏洞 4：循环内重复分配，只在最后释放最后一次 */
void leak_in_loop(int n) {
    char *p = NULL;
    for (int i = 0; i < n; i++) {
        p = (char *)malloc(32); /* leak: 每次循环都泄漏一次 */
        if (!p) return;
        p[0] = (char)('a' + i);
    }
    free(p);                    /* 只释放了最后一次 */
}

/* 漏洞 5：文件句柄泄漏 */
void file_handle_leak(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    if (fgets(line, sizeof(line), f) == NULL) {
        return;                 /* leak: f 未 fclose */
    }
    if (line[0] == '#') {
        return;                 /* leak: f 未 fclose */
    }
    printf("first line: %s", line);
    fclose(f);
}

/* 对照组 1：所有路径都正确释放 */
int safe_alloc_and_free(int n) {
    int *arr = (int *)malloc(sizeof(int) * 100);
    if (!arr) return -1;

    if (n < 0 || n > 1000) {
        free(arr);              /* 在所有错误路径都释放 */
        return -1;
    }

    for (int i = 0; i < n; i++) arr[i] = i;
    free(arr);
    return 0;
}

/* 对照组 2：使用 goto 统一清理 */
int safe_with_goto(const char *path) {
    FILE *f = NULL;
    char *buf = NULL;
    int ret = -1;

    f = fopen(path, "r");
    if (!f) goto cleanup;

    buf = (char *)malloc(256);
    if (!buf) goto cleanup;

    if (fgets(buf, 256, f) == NULL) goto cleanup;
    ret = 0;

cleanup:
    if (buf) free(buf);
    if (f) fclose(f);
    return ret;
}

int main(void) {
    simple_leak();
    leak_on_error(-1);
    leak_overwrite();
    leak_in_loop(3);
    file_handle_leak("/tmp/test.txt");
    safe_alloc_and_free(10);
    safe_with_goto("/tmp/test.txt");
    return 0;
}
