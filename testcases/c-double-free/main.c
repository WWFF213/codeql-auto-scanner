/*
 * Double Free test case for CodeQL.
 *
 * 包含四种漏洞模式 + 安全对照组：
 *   1. simple_double_free   - 同一指针连续 free 两次
 *   2. cond_double_free     - 条件分支中再次 free
 *   3. alias_double_free    - 通过别名指针 free 两次
 *   4. cleanup_double_free  - 清理函数 + main 都 free
 *   5. safe_*               - 安全写法
 */
#include <stdio.h>
#include <stdlib.h>

/* 漏洞 1：直接连续 free */
void simple_double_free(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    free(p);
    free(p);                    /* double free */
}

/* 漏洞 2：条件分支中重复 free */
void cond_double_free(int flag) {
    int *arr = (int *)malloc(sizeof(int) * 10);
    if (!arr) return;
    if (flag) {
        free(arr);
    }
    free(arr);                  /* 当 flag 为真时为 double free */
}

/* 漏洞 3：别名指针 - 两个指针指向同一块内存 */
void alias_double_free(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *q = p;                /* q 是 p 的别名 */
    free(p);
    free(q);                    /* double free（q 与 p 指向同一地址） */
}

/* 漏洞 4：辅助函数已释放，调用者再次释放 */
static void cleanup(int *buf) {
    free(buf);
}

void cleanup_double_free(void) {
    int *data = (int *)malloc(sizeof(int) * 16);
    if (!data) return;
    data[0] = 42;
    cleanup(data);
    free(data);                 /* double free：cleanup 内已经 free 过 */
}

/* 对照组 1：free 后置 NULL，再次 free 是无害操作 */
void safe_double_free(void) {
    char *p = (char *)malloc(32);
    if (!p) return;
    free(p);
    p = NULL;
    free(p);                    /* free(NULL) 是 C 标准允许的 no-op */
}

/* 对照组 2：所有路径只 free 一次 */
void safe_branch(int flag) {
    int *arr = (int *)malloc(sizeof(int) * 10);
    if (!arr) return;
    if (flag) {
        free(arr);
        return;
    }
    free(arr);
}

int main(void) {
    simple_double_free();
    cond_double_free(1);
    alias_double_free();
    cleanup_double_free();
    safe_double_free();
    safe_branch(0);
    return 0;
}
