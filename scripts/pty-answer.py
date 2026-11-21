"""Run a command on a pseudo-terminal, typing a password at its prompts.

    PTY_PASSWORD=... [PTY_DEADLINE=seconds] python3 -I scripts/pty-answer.py CMD [ARG...]

The test scripts (test-agent-install.sh, test-codesign-local.sh) use it to
drive the interactive paths of `make install` the way a person at a terminal
would: whenever the output so far contains "assword" and ends in ":", it
types PTY_PASSWORD and a newline. What the terminal showed is printed, and
the exit status is the command's.

At the deadline (default 120 seconds) the command's whole process group is
killed and reaped, and the exit status is 124. A prompt nobody answers then
fails the test instead of hanging it.
"""

import os
import pty
import select
import signal
import sys
import time

password = os.environ["PTY_PASSWORD"].encode()
limit = float(os.environ.get("PTY_DEADLINE", "120"))
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
deadline = time.time() + limit
seen, pending = b"", b""


def give_up(*_):
    # pty.fork made the child a session leader, so its process group is its
    # pid: kill the whole group and reap it.
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        # The group already exited on its own: nothing is left to kill, and
        # waitpid below still reaps the child.
        pass
    os.waitpid(pid, 0)
    sys.stdout.write(seen.decode(errors="replace"))
    sys.stdout.write("\npty-answer: gave up after %gs\n" % limit)
    sys.exit(124)


while True:
    remaining = deadline - time.time()
    if remaining <= 0:
        give_up()
    if not select.select([fd], [], [], min(remaining, 0.5))[0]:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    seen += data
    pending += data
    if b"assword" in pending and pending.rstrip().endswith(b":"):
        os.write(fd, password + b"\n")
        pending = b""

# The terminal closed; the command may still be running. Wait for it, but
# only until the deadline.
remaining = deadline - time.time()
if remaining <= 0:
    give_up()
signal.signal(signal.SIGALRM, give_up)
signal.setitimer(signal.ITIMER_REAL, remaining)
_, status = os.waitpid(pid, 0)
signal.setitimer(signal.ITIMER_REAL, 0)
sys.stdout.write(seen.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
