/**
 * SPDX-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2018, Red Hat, Inc.
 *
 * Unit test framework.
 */

#ifndef OPENLLDP_UNIT_TEST
#define OPENLLDP_UNIT_TEST

#include <stddef.h>

struct test_case
{
    const char *name;
    int (*test_fn)(void);
};

struct test_result
{
    struct test_case *tc;
    int result;
};

struct test_suite
{
    const char *name;

    struct test_result *tests_pass;
    struct test_result *tests_fail;

    size_t tests_fail_cnt;
    size_t tests_pass_cnt;

    struct test_case *cases;
    size_t tests_cnt;
};

void hook_stdout(void);
void unhook_stdout(void);

/* Adds a test case to a test suite */
void register_test_case(struct test_suite *, const char *,
                        int (*test_fn)(void));

/* Records a test failure.  NOTE: recording a failure is NOT thread safe. */
void record_test_failure(struct test_suite *, struct test_case *, int);

/* Records a test success.  NOTE: recording a success is NOT thread safe. */
void record_test_pass(struct test_suite *, struct test_case *);

/* prints the test results.  NOTE: this operation is not thread safe. */
void report_test_results(struct test_suite *);

static inline void run_test_suite(struct test_suite *ts)
{
    struct test_case *tc;
    size_t test;

    for (test = 0, tc = ts->cases; test < ts->tests_cnt; test++, tc++) {
        int result = tc->test_fn();

        if (result) {
            record_test_failure(ts, tc, result);
        } else {
            record_test_pass(ts, tc);
        }
    }
}

#endif
