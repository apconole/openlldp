/**
 * SPDX-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2018, Red Hat, Inc.
 *
 * Unit test for basman functions
 */

#include "lldp.h"
#include "units.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void print_mng_addr(u16 len, char *info);

static int test_mgmt_printing()
{
    char *mgmt_info_test;
    int result = 1;
    FILE *output;
    int ctr = 0;

    /* since we are testing the output, grab stdout */
    hook_stdout();
    
    mgmt_info_test =
        "05010a2ff8f9" /* addrlen + subtype + addr */
        "0100000000" /* if-subtype + ifnum */
        "0c0103060102011f0101010100" /* oid-len + oid */
        ;

    print_mng_addr(strlen(mgmt_info_test), mgmt_info_test);
    fflush(stdout);

    output = fopen("stdout_test.txt", "r");
    if (!output)
        goto done;

    while (!feof(output) && ctr != 3) {
        char buf[1024];
        if (!fgets(buf, sizeof(buf), output))
            goto done;

        if (!strcmp(buf, "IPv4: 10.47.248.249\n"))
            ctr++;
        else if (!strcmp(buf, "\tUnknown interface subtype: 0\n"))
            ctr++;
        else if (!strcmp(buf, "\tOID: 0.1.3.6.1.2.1.31.1.1.1.1.0\n"))
            ctr++;
        else {
            fprintf(stderr, "FATAL: unknown line '%s'\n", buf);
            goto done;
        }
    }

    result = 0;

done:
    if (output)
        fclose(output);

    unhook_stdout();
    return result;
}

int main(void)
{
    struct test_suite basman_suite = { .name = "basman" };

    register_test_case(&basman_suite, "mgmt_print", test_mgmt_printing);

    run_test_suite(&basman_suite);

    report_test_results(&basman_suite);
    return 0;
}
