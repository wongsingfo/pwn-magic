# PWN Magic

This repo includes some PWN tricks in common use and provides a PWN environment.

## Build and Run

Run only one command at current directory:

```
docker-compose up -d
```

Visit `http://localhost:8888` to open JupyterLab. You can access the terminal of the container in the JupyterLab or running:

```
docker exec -it ctf /bin/bash
```

## GDB debug

First, open a tmux session. The pwnlib invokes GDB in the most recently used tmux session with the following setting:

```
from pwn import context
context.terminal = ['tmux', 'new-window']
```

Second, prepare the program that we want to debug:

```
from pwn import gdb
gdb.debug(['./prog'])
```

Read `rop/README.ipynb` to see the details.
