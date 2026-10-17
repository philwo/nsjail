#!/bin/sh
# Checks that nsjail doesn't kill a jail before its time limit. SIGCHLD makes
# nsjail check the time limit, so the loop makes it check about every 10 ms.
# A check that rounds the run time up kills the jail in about 80% of runs.

for i in 1 2 3; do
	./nsjail --config tests/basic.cfg -q -t 1 -- /bin/sleep 0.8 < /dev/null &
	pid=$!
	while kill -CHLD "$pid" 2> /dev/null; do
		sleep 0.01
	done
	wait "$pid" || exit $?
done
