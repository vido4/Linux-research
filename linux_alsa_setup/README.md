# Motivation
In my off-time I wanted to attempt attacking some more difficult target. With it's big community, bug bounties and available source code I went with Linux kernel, which is fairly popular target nowadays (and quite hardened with that). 
Starting with a lot of reading, I went thorugh gorgeous [course](https://pawnyable.cafe/linux-kernel/) (In japanese, but with translator its easily doable - highly recommend! @ptrYudai is a boss). Another great resource for 
helping understanding SLUB allocator was [this one](https://sam4k.com/linternals-introduction/). There were of course also tons of other random articles on the internet which I do not remember which supplemented my learning. Having done 
that, I wanted to dive deep into exploiting some old vulnerabilities. So my goal for this research was:
  * Finding some fixed kernel bug that could be exploited without existing PoC
  * Try to reproduce that and possibly turn it into working exploit?

The exploitation part did not quite work out, but it was still quite a journey. Aside from attempting to exploit the bug I also went on the lookout what other vulnerabilities could exist there and trying to understand how it all works.

# Target
So I started off with naive strategy of just going to Linux github repository and searching for some keywords like CVE, Use-After-Free, Overflow and similar. One of the commits got my attention, 
namely [this](https://github.com/torvalds/linux/commit/56b88b50565cd8b946a2d00b0c83927b7ebb055e). It basically has it all: UAF keyword, assigned CVE, relatively new bug and even described path when the issue happens. 
Not knowing much about various kernel parts, I only knew ALSA has something to do with the sound. Looks like a perfect target, so not thinking much about it I went off with trying to creating some PoC.

# Environment
First thing to do is build proper version of Linux kernel. We can get any version of kernel we are interested in from github and checkout right before the patch. I went with the route of checking to what existing tags was the patch applied to
![image](https://github.com/vido4/Linux-research/assets/5321740/6caaed06-7327-4b3d-bb81-7c5e7c16d71d)

Seeing that the patch ended on v6.2-rc4, I simply downloaded tag v6.2-rc3 which should still have the vulnerability (as these are release-candidates I guess there is no point to every one of them?)
In the unpacked directory of Linux, then we do `make menuconfig` and set up what kernel options we want.

There are not much changes I made. Need to make sure we have `Debug information` and `Provide GDB scripts for kernel debugging` on 
![image](https://github.com/vido4/Linux-research/assets/5321740/83dc17c6-8e53-45e9-9659-b10d2230331c)

Another thing is - since we need to use ALSA, we need to set up some sound card drivers. Important thing - normally most drivers are built as kernel modules (M letter when selecting it in menuconfig). 
To save the hassle we just build then directly into the kernel - selected all of them here which is not necessary as we will use single one, but does not hurt, 
any driver should be find (as long as we can emulate it with qemu).

![image](https://github.com/vido4/Linux-research/assets/5321740/a4894951-d137-4939-8279-a74ab92eff82)

With all set we can save config and build the kernel with `make -j$(nproc)` (it can take a while)

After this - we also need to have legitimate filesystem aside from kernel to have fully functioning system. For that purpose the easieset way is using [buildroot](https://buildroot.org/) - we can select whatever packaged we need there. 
I prefer to opt for ulibc instead of glibc so the system is not bloated and busybox.

Additionally I use cttyhack so we can freely boot and be logged in into the interactive system. It can be done by modifying config in `buildroot/package/busybox/busybox.config` and enabling options
```
CONFIG_SETUIDGID=y
CONFIG_CTTYHACK=y
```

I build filesystem in `.cpio` file format.
Finally I have two scripts inspired by ptr-yudai to compile exploit, repack filesystem and run qemu.

transfer.sh
```bash
 #!/bin/sh
 gcc exploit.c -o exploit -static -masm=intel -m32 -lpthread
 mv exploit root
 cd root; find . -print0 | cpio -o --null --format=newc --owner=root > ../debugfs.cpio
 cd ../

 sh run.sh
```

and run.sh
```bash
 qemu-system-x86_64 \
     -m 1G \
     -nographic \
     -kernel bzImage \
     -append "console=ttyS0 loglevel=3 kpti=on nokaslr" \
     -no-reboot \
     -cpu qemu64,+smap,+smep \
     -smp 2 \
     -monitor /dev/null \
     -initrd debugfs.cpio \
     -net nic,model=virtio \
     -net user \
     -soundhw hda \
     -s
```

For starters we go with no KASLR - but all of these options can be modified afterwards. `-smp 2` is important since we will be racing to exploit vulnerability, 
so more than 1 core is required. `-soundhw` emulates `hda` sound card and `-s` allows us to attach gdb. We are quite generous with 1G RAM but it can be easily lowered (just not too much). 
Rest of the options is nothing special and is nicely described in `qemu` help. 

# Code exploration
Now that we have stable environment for testing, we need to know how to trigger the vulnerable function - and how it all works. For starters I just went through the ALSA code understanding what can be done there 
and looking for potential interesting places from security perspective instead of going straight to the bug.

