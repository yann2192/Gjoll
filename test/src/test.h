#ifndef GJOLL_TEST_H
#define GJOLL_TEST_H

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
    if (message) return message; } while (0)
#define mu_run(test) do { char *message = test(); \
    if (message) return message; } while (0)

int tests_run;

char* header_tests();
char* crypto_tests();

#endif
