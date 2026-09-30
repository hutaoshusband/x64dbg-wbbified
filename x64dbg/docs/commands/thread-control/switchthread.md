# switchthread/threadswitch

Switch the internal current thread to another thread (resulting in different callstack + different registers displayed).

## arguments

`[arg1]` ThreadId of the thread to switch to (see the Threads tab). When not specified, the main thread is used.

`[arg2]` Options. If it contains "silent" or "quiet", the "Thread switched!" message is suppressed and the GUI update completes before the command returns. This allows callers such as the Call Stack view to perform follow-up navigation without it being overridden by a pending thread-switch update.

## result

This command does not set any result variables.
