## What is this?

POSIX process API on Windows 2000 and later. (Our primary _test_ targets at the moment are Windows 8.1 and Windows 10.)

Due to the nature of application containers, expect desktop (traditional) app model support only.

## Is it ready to use?

We follow the planning system outlined in _The Pipe and the Pitcher_: "One berry I pick, at another I look, a third one I notice, a fourth one I fancy."

method|POSIX header|Windows header|provided by/planning tier|notes
--|--|--|--
`exit`|`unistd.h`|`stdlib.h`|[UCRT](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/exit-exit-exit)|a universal human right
`exec*`|`unistd.h`|`process.h`[UCRT](https://learn.microsoft.com/en-us/cpp/c-runtime-library/exec-wexec-functions)|
`fexecve`|`unistd.h`|-|tier 4 "I fancy"|execute a program specified via its file descriptor
`fork`|`unistd.h`|tier 1 "I pick"|idiomatically collaborative with `exec` (*)
`getpgid` `getpgrp`|`unistd.h`|-|set/get process group
getpid getppid	get process identification
getsid	get session ID
nice	change process priority
setpgid
setpgrp
setsid	creates a session and sets the process group ID
sleep	sleep for a specified number of seconds
tcgetpgrp
tcsetpgrp

## But there is Cygwin/MSys/MinGW/you name it…

We _do_ target MinGW, but its POSIX process API (or [user API](https://github.com/treeswift/libwusers), for that matter) implementation is incomplete.

As for Cygwin et al, see the next chapter.

## Is it GPL/AGPL/LGPL/LBGTQIGPL?

We are committed to releasing our code into the public domain + under [effectively equivalent terms](LICENSE) in jurisdictions that don't recognize one.

## Why the name?

Because forks. (Yes, `fork()`s.)

## Is there a code of conduct?

Be kind. (Or, well, fork and then whatever.)
