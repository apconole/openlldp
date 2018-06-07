#include "units.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static size_t extend_test_result(struct test_result **tr, size_t n)
{
    struct test_result *new_tr = realloc(*tr,
                                         sizeof(struct test_result) * (n + 1));
    if (!new_tr) {
        fprintf(stderr, "FATAL: unable to extend test result array.\n");
        raise(SIGABRT);
    }

    *tr = new_tr;
    return n + 1;
}

void record_test_failure(struct test_suite *ts, struct test_case *tc, int rs)
{
    ts->tests_fail_cnt = extend_test_result(&ts->tests_fail,
                                            ts->tests_fail_cnt);
    ts->tests_fail[ts->tests_fail_cnt-1].tc = tc;
    ts->tests_fail[ts->tests_fail_cnt-1].result = rs;
}

void record_test_pass(struct test_suite *ts, struct test_case *tc)
{
    ts->tests_pass_cnt = extend_test_result(&ts->tests_pass,
                                            ts->tests_pass_cnt);
    ts->tests_pass[ts->tests_pass_cnt-1].tc = tc;
    ts->tests_pass[ts->tests_pass_cnt-1].result = 0;
}

void register_test_case(struct test_suite *ts, const char *name,
                        int (*test_fn)(void))
{
    struct test_case *new_tc = realloc(ts->cases,
                                       sizeof(struct test_case) *
                                       (ts->tests_cnt + 1));
    if (!new_tc) {
        fprintf(stderr, "FATAL: unable to register test case '%s'\n", name);
        raise(SIGABRT);
    }

    ts->cases = new_tc;
    ts->cases[ts->tests_cnt].name = name;
    ts->cases[ts->tests_cnt].test_fn = test_fn;
    ts->tests_cnt++;
}

void report_test_results(struct test_suite *ts)
{
    size_t tr_cnt;
    struct test_result *tr;

    fprintf(stderr, "====== Test suite '%s' results ======\n", ts->name);

    fprintf(stderr, "Total tests executed: %zu\n\n",
            ts->tests_fail_cnt + ts->tests_pass_cnt);

    fprintf(stderr, "Successes: %zu\n", ts->tests_pass_cnt);
    fprintf(stderr, "=====================\n");

    for (tr_cnt = 0, tr = ts->tests_pass;
         tr_cnt < ts->tests_pass_cnt;
         tr_cnt++, tr++) {
        fprintf(stderr, "Test Passed: '%s'\n", tr->tc->name);
    }

    fprintf(stderr, "Failures: %zu\n", ts->tests_fail_cnt);
    fprintf(stderr, "=====================\n");
    for (tr_cnt = 0, tr = ts->tests_fail;
         tr_cnt < ts->tests_fail_cnt;
         tr_cnt++, tr++) {
        fprintf(stderr, "Test Failed: '%s'\n", tr->tc->name);
    }

    if (ts->tests_fail_cnt) {
        exit(1);
    }
}

static int hook_fd = -1;
static FILE *stdout_hook;

void hook_stdout()
{
    if (hook_fd == -1) {
        hook_fd = dup(STDOUT_FILENO);
        stdout_hook = freopen("stdout_test.txt", "w", stdout);
    }
}

void unhook_stdout()
{
    if (hook_fd != -1) {
        dup2(hook_fd, STDOUT_FILENO);
        stdout = fdopen(STDOUT_FILENO, "w");
        close(hook_fd);
        hook_fd = -1;
    }
}
