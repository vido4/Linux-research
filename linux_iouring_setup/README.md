# IO Uring exercise
I wanted to go into io_uring internals - as it was such a hot topic lately. Also hoped I could do some bug variant hunting when I understand a specific bug. I went with [this](https://github.com/torvalds/linux/commit/4c17a496a7a0730fdfc9e249b83cc58249111532) 
bug for a few reasons. It seems pretty straightforward, was patched almost immediately after introducing and did not go into any stable distribution - so there is no harm done even if it's weaponized. 
I sincerely doubt anyone used that particular RC kernel version other than for testing.

I will maybe make some time to make detailed description of my approach, but likely not coming soon. Code quality is bad as it is one-shot thing for exercise.

# Short description
Basically I wanted to find a way to abuse msg_msg as a victim object for arbitrary write, regardless of kmalloc cache size. 
I digged into that only with assumption that it is doable based on [this](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html). 
While I went on to achieve write with the help of FUSE, the end result is basically [that](https://syst3mfailure.io/wall-of-perdition/). Only went to read the second blog after figuring it out. 
I had some other condition in manipulating UAF victim object. Final result is rewriting `cred` of `task_struct` with reasonable stability.

It could be improved to take into account some mitigations - I had disabled freelist randomisation and hardening (that one for trivial double-free abuse), but stability would most likely go down.
Anyway it should be double not like any of mitigations would completely axe the exploit.
