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

There are not much changes I made. To select an option, navigate to it using arrows/enter key and set it using `Y/N` key. First we need to make sure we have `Debug information` and `Provide GDB scripts for kernel debugging` on 
![image](https://github.com/vido4/Linux-research/assets/5321740/83dc17c6-8e53-45e9-9659-b10d2230331c)

Another thing is - since we need to use ALSA, we need to set up some sound card drivers. Important thing - normally most drivers are built as kernel modules (M letter when selecting it in menuconfig). 
To save the hassle we just build then directly into the kernel. 
Options I selected for that are

![image](https://github.com/vido4/Linux-research/assets/5321740/a2c496ac-2e8b-4df5-a10c-0f8f273fb96f)

With all set we can save config and build the kernel with `make -j$(nproc)` (it can take a while)

As a result we should have `vmlinux` binary which is compiler kernel with debug symbols to be used for debugging in Linux root directory. Additionally, in `arch/x86/boot/` (change `x86` to any target arch when not targeting x86/64 - for x64 it's still this directory) there is `bzImage` which is compressed image used in `qemu`.

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
Now that we have stable environment for testing, we need to know how to trigger the vulnerable function - and how it all works. For starters I just went through the ALSA code understanding what can be done there and looking for potential interesting places from security perspective.

Looking at the patch we see functions which are used in this functionality - flow starts with `snd_ctl_ioctl` function and `snd_ctl_ioctl_compat` before reaching vulnerable function.

![image](https://github.com/vido4/Linux-research/assets/5321740/2667782a-328f-40fb-a470-a65b8ad53dd7)

To go through the source code I have setup vim with `cscope` which nicely indexes all references to functions and names. However often I simply go to online [viewer](https://elixir.bootlin.com/linux/v6.2-rc3/source/) where we can select specific version and search for references through web. In this case it works nicely, but when I want to go through source on specific commit it's not really viable.

Function `snd_ctl_ioctl` is defined in file `sound/core/control.c`. Looking through the file we can find all operations that can be performed on the device:
```c
static const struct file_operations snd_ctl_f_ops =
{
	.owner =	THIS_MODULE,
	.read =		snd_ctl_read,
	.open =		snd_ctl_open,
	.release =	snd_ctl_release,
	.llseek =	no_llseek,
	.poll =		snd_ctl_poll,
	.unlocked_ioctl =	snd_ctl_ioctl,
	.compat_ioctl =	snd_ctl_ioctl_compat,
	.fasync =	snd_ctl_fasync,
};
```

Registering `ctl` device is done with `snd_ctl_dev_register` which, going few levels up, is at the start called by `snd_card_new`. This one is called by various drivers and not from anything reachable from userland, hence why we require emulation of sound card. 
![image](https://github.com/vido4/Linux-research/assets/5321740/fba6cf15-b0bb-406a-8cf0-b3fa9ba34e56)

Then, in function `snd_ctl_create` (which is called by `snd_card_new` and eventually calls `snd_ctl_dev_register`) we can find line
```c
dev_set_name(&card->ctl_dev, "controlC%d", card->number);
```

Which tells us the name of the registered device through which we can communicate. Going through the filesystem, we can find that this control exists in `/dev/snd`. So now let's prove that we can access these functionalities by interacting with `/dev/snd/controlC0`

### Debugging setup
Having done all the steps correctly so far, debugging kernel is really easy. I recommend [pwndbg](https://github.com/pwndbg/pwndbg) plugin for `gdb` to have neat output. In one terminial window, simply go to Linux source root directory and type
```bash
gdb vmlinux
```
It will load all kernel symbols in that instance. Afterwards, we want to break in the `snd_ctl_open` function since this is the initial step in interacting with our control.
```
break snd_ctl_open
target remote:1234
c
```
Line `target remote:1234` will connect to our qemu instance on port `1234` - default port that `qemu` is listening on when using `-s` switch.

Then we just need a snippet of code which will do the open for us. This should suffice for now: 
```c
#include <fcntl.h>
#include <stdio.h>

int main(){
    int fd = open("/dev/snd/controlC0", O_RDWR);
    if (fd == -1){
        printf("[!] ERROR\n");
    }else{
        printf("[+] SUCCESS\n");
    }
}
```
If we save it as `exploit.c` file, script `transfer.sh` takes care of compiling it and repacking the filesystem. Result file will be on the target system at `/exploit`. After running it, breakpoint should be triggered.

![image](https://github.com/vido4/Linux-research/assets/5321740/5aef67aa-4223-484e-9dbf-5b69c17e815e)

We also get nice source code view because we are running it from Linux source code directory, so all sources are available.

## Finding the issue
Having the initial setup ready, we can go see how to trigger the issue. In the meantime, I spent lots of time reading every function from initialization of the control to all possible actions we can do. It was surely educational, but at the end I did not find any reasonable issue that way, so I went back into attempting to trigger the vulnerability.

