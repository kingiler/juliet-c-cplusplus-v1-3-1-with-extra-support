#ifdef __FreeBSD__

#include <sys/cdefs.h>

#undef gets

__sym_compat(gets, unsafe_gets, FBSD_1.0);
char *unsafe_gets(char *);

static char *gets(char *buf) { return unsafe_gets(buf); }

#endif

