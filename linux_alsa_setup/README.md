# CVE-2023-0266
## How to run
Qemu is required to run these examples, make sure you have it properly installed. 

Then simply run 
```bash
run.sh
```
If you want to modify exploit - first unpack `cpio` with 
```bash
sh unpack.sh
```
Then after modifying `poc.c` file run with 
```bash
transfer.sh
```
It will repack `cpio` filesystem including compiled `poc`

Exploit is located at `/poc` inside the vm.

## Motivation
In my off-time I wanted to attempt attacking some more difficult target. With it's big community, bug bounties and available source code I went with Linux kernel, which is fairly popular target nowadays (and quite hardened with that). 
Starting with a lot of reading, I went thorugh gorgeous [course](https://pawnyable.cafe/linux-kernel/) (In japanese, but with translator its easily doable - highly recommend! @ptrYudai is a boss). Another great resource for 
helping understanding SLUB allocator was [this one](https://sam4k.com/linternals-introduction/). There were of course also tons of other random articles on the internet which I do not remember which supplemented my learning. Having done 
that, I wanted to dive deep into exploiting some old vulnerabilities. So my goal for this research was:
  * Finding some fixed kernel bug that could be exploited without existing PoC
  * Try to reproduce that and possibly turn it into working exploit?

The exploitation part did not quite work out, but it was still quite a journey. Aside from attempting to exploit the bug I also went on the lookout what other vulnerabilities could exist there and trying to understand how it all works.

## Target
So I started off with naive strategy of just going to Linux github repository and searching for some keywords like CVE, Use-After-Free, Overflow and similar. One of the commits got my attention, 
namely [this](https://github.com/torvalds/linux/commit/56b88b50565cd8b946a2d00b0c83927b7ebb055e). It basically has it all: UAF keyword, assigned CVE, relatively new bug and even described path when the issue happens. 
Not knowing much about various kernel parts, I only knew ALSA has something to do with the sound. Looks like a perfect target, so not thinking much about it I went off with trying to creating some PoC.

## Environment
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

## Code exploration
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

MAKE SURE that `/dev/snd/controlC0` has R/W permissions for everyone! Typical distros like Ubuntu do not have it setup like that, but allow users to read/write to that using extended attributes so this path should be achievable by unauthenticated users in most scanarios.

## Finding the issue
Having the initial setup ready, we can go see how to trigger the issue. In the meantime, I spent lots of time reading every function from initialization of the control to all possible actions we can do. It was surely educational, but at the end I did not find any reasonable issue that way, so I went back into attempting to trigger the vulnerability.

First, look at how properly the flow at 64 bit works. The sequence of calls according to patch is 
```
snd_ctl_ioctl
  snd_ctl_elem_read_user
    [takes controls_rwsem]
    snd_ctl_elem_read [lock properly held, all good]
    [drops controls_rwsem]
```

Function `snd_ctl_ioctl` is typical `ioctl` handler which can be called with syscall `ioctl`. Various operations are implemented there, which depend on `cmd` argument priovided by user. These are:
```c
switch (cmd) {
	case SNDRV_CTL_IOCTL_PVERSION:
		return put_user(SNDRV_CTL_VERSION, ip) ? -EFAULT : 0;
	case SNDRV_CTL_IOCTL_CARD_INFO:
		return snd_ctl_card_info(card, ctl, cmd, argp);
	case SNDRV_CTL_IOCTL_ELEM_LIST:
		return snd_ctl_elem_list_user(card, argp);
	case SNDRV_CTL_IOCTL_ELEM_INFO:
		return snd_ctl_elem_info_user(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_READ:
		return snd_ctl_elem_read_user(card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE:
		return snd_ctl_elem_write_user(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
		return snd_ctl_elem_lock(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
		return snd_ctl_elem_unlock(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_ADD:
		return snd_ctl_elem_add_user(ctl, argp, 0);
	case SNDRV_CTL_IOCTL_ELEM_REPLACE:
		return snd_ctl_elem_add_user(ctl, argp, 1);
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
		return snd_ctl_elem_remove(ctl, argp);
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
		return snd_ctl_subscribe_events(ctl, ip);
	case SNDRV_CTL_IOCTL_TLV_READ:
		down_read(&ctl->card->controls_rwsem);
		err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_READ);
		up_read(&ctl->card->controls_rwsem);
		return err;
	case SNDRV_CTL_IOCTL_TLV_WRITE:
		down_write(&ctl->card->controls_rwsem);
		err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_WRITE);
		up_write(&ctl->card->controls_rwsem);
		return err;
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
		down_write(&ctl->card->controls_rwsem);
		err = snd_ctl_tlv_ioctl(ctl, argp, SNDRV_CTL_TLV_OP_CMD);
		up_write(&ctl->card->controls_rwsem);
		return err;
	case SNDRV_CTL_IOCTL_POWER:
		return -ENOPROTOOPT;
	case SNDRV_CTL_IOCTL_POWER_STATE:
		return put_user(SNDRV_CTL_POWER_D0, ip) ? -EFAULT : 0;
	}
```

When we see the definition of these values (like `SNDRV_CTL_IOCTL_ELEM_READ`) these are defined with some interesting macros for example
```c
#define SNDRV_CTL_IOCTL_ELEM_READ	_IOWR('U', 0x12, struct snd_ctl_elem_value)
```
In this case `U` is a value assigned to `snd_ctl_ioctl` calls (so it's not mistaken with other ioctls), `0x12` is specific call in this ioctl type and third argument is size of used structure for this function.
Resulting value is represented as
```
| R/W  |SIZE(struct)|TYPE    | NR     |
|2 bits| 14 bits    | 8 bits | 8 bits |

Our example SNDRV_CTL_IOCTL_ELEM_READ = 0xc4c85512
| WR[0x3] | sizeof(struct snd_ctl_elem_value)[0x4c8] | 'U'[0x55] | 0x12 |

```

Function `snd_ctl_elem_read_user` is executed when we provide cmd `SNDRV_CTL_IOCTL_ELEM_READ`

All it basically does is: 
* duplicating user-provided data so its in kernel space
* taking lock `&card->controls_rwsem`
* doing real read `snd_ctl_elem_read`
* returning result to user through `copy_to_user`

```c
static int snd_ctl_elem_read_user(struct snd_card *card,
				  struct snd_ctl_elem_value __user *_control)
{
	struct snd_ctl_elem_value *control;
	int result;

	control = memdup_user(_control, sizeof(*control));
	if (IS_ERR(control))
		return PTR_ERR(control);

	down_read(&card->controls_rwsem);
	result = snd_ctl_elem_read(card, control);
	up_read(&card->controls_rwsem);
	if (result < 0)
		goto error;

	if (copy_to_user(_control, control, sizeof(*control)))
		result = -EFAULT;
 error:
	kfree(control);
	return result;
}
```

Then in `snd_ctl_elem_read`
* We find `kctl` with provided `id`
* check if it can be read
* perform read with `kctl->get()`
  
```c
static int snd_ctl_elem_read(struct snd_card *card,
			     struct snd_ctl_elem_value *control)
{
	struct snd_kcontrol *kctl;
	struct snd_kcontrol_volatile *vd;
	unsigned int index_offset;
	struct snd_ctl_elem_info info;
	const u32 pattern = 0xdeadbeef;
	int ret;

	kctl = snd_ctl_find_id(card, &control->id);
	if (kctl == NULL)
		return -ENOENT;

	index_offset = snd_ctl_get_ioff(kctl, &control->id);
	vd = &kctl->vd[index_offset];
	if (!(vd->access & SNDRV_CTL_ELEM_ACCESS_READ) || kctl->get == NULL)
		return -EPERM;

	snd_ctl_build_ioff(&control->id, kctl, index_offset);

#ifdef CONFIG_SND_CTL_DEBUG
	/* info is needed only for validation */
	memset(&info, 0, sizeof(info));
	info.id = control->id;
	ret = __snd_ctl_elem_info(card, kctl, &info, NULL);
	if (ret < 0)
		return ret;
#endif

	if (!snd_ctl_skip_validation(&info))
		fill_remaining_elem_value(control, &info, pattern);
	ret = snd_power_ref_and_wait(card);
	if (!ret)
		ret = kctl->get(kctl, control);
	snd_power_unref(card);
	if (ret < 0)
		return ret;
	if (!snd_ctl_skip_validation(&info) &&
	    sanity_check_elem_value(card, control, &info, pattern) < 0) {
		dev_err(card->dev,
			"control %i:%i:%i:%s:%i: access overflow\n",
			control->id.iface, control->id.device,
			control->id.subdevice, control->id.name,
			control->id.index);
		return -EINVAL;
	}
	return ret;
}
```

When looking at the patch - it is said that in the 32-bit case lock is taken incorrectly, so first let's compare the flow.
It is (kinda differnt from the patch, had some typo?)
```
snd_ctl_ioctl_compat
   snd_ctl_elem_read_user_compat
      ctl_elem_write_read
         ctl_elem_read_user
            snd_ctl_elem_read[missing lock]
```

First of all - we start off with `snd_ctl_ioctl_compat`. How can we reach that ?

It turns out, whenever a 32 bit application calls a `ioctl` syscall, it will be handled by `ioctl_compat` handler instead of standard `ioctl` one. Why? Because the arguments need to be adjusted. for example `sizeof(long)` is different for 32 and 64 bit application
which can create problems down-the-line. This handler is actually defined in `sound/core/control_compat.c` file.

A big chunk of cmds is simply passed through to `snd_ctl_ioctl` but there are some exceptions. 
```c
static inline long snd_ctl_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct snd_ctl_file *ctl;
	struct snd_kctl_ioctl *p;
	void __user *argp = compat_ptr(arg);
	int err;

	ctl = file->private_data;
	if (snd_BUG_ON(!ctl || !ctl->card))
		return -ENXIO;

	switch (cmd) {
	case SNDRV_CTL_IOCTL_PVERSION:
	case SNDRV_CTL_IOCTL_CARD_INFO:
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
	case SNDRV_CTL_IOCTL_POWER:
	case SNDRV_CTL_IOCTL_POWER_STATE:
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
		return snd_ctl_ioctl(file, cmd, (unsigned long)argp);
	case SNDRV_CTL_IOCTL_ELEM_LIST32:
		return snd_ctl_elem_list_compat(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_INFO32:
		return snd_ctl_elem_info_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_READ32:
		return snd_ctl_elem_read_user_compat(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE32:
		return snd_ctl_elem_write_user_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_ADD32:
		return snd_ctl_elem_add_compat(ctl, argp, 0);
	case SNDRV_CTL_IOCTL_ELEM_REPLACE32:
		return snd_ctl_elem_add_compat(ctl, argp, 1);
#ifdef CONFIG_X86_X32_ABI
	case SNDRV_CTL_IOCTL_ELEM_READ_X32:
		return snd_ctl_elem_read_user_x32(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE_X32:
		return snd_ctl_elem_write_user_x32(ctl, argp);
#endif /* CONFIG_X86_X32_ABI */
```

So indeed, going into the command `SNDRV_CTL_IOCTL_ELEM_READ32`, down to `ctl_elem_read_user` we can notice that there is no lock `&card->controls_rwsem` taken before going to `snd_ctl_elem_read`

```c
static int ctl_elem_read_user(struct snd_card *card,
			      void __user *userdata, void __user *valuep)
{
	struct snd_ctl_elem_value *data;
	int err, type, count;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	err = copy_ctl_value_from_user(card, data, userdata, valuep,
				       &type, &count);
	if (err < 0)
		goto error;

	err = snd_ctl_elem_read(card, data);
	if (err < 0)
		goto error;
	err = copy_ctl_value_to_user(userdata, valuep, data, type, count);
 error:
	kfree(data);
	return err;
}
```

How can we abuse it then?

### Locking
First of all - why is locking necessary? Kernel functions can be called simultanously by multiple threads or processes and the will be processed concurrently. If we modify some globally accessible data, when it is handled by some other function at the same time, we can subvert functions' expectations. 
Simple example would be read/write operation on object. We could have read function which performs some initial check on object (if proper index is passed) and if it is true, reads data from internal array at that index. If we can simultanously write to that object. We could bypass this check while writing arbitrary index there.
```
  Thread1         Thread2
 ------------        |	
 |READ INDEX|        |
 ------------        |
      |              v
      |        -------------
      |        |WRITE INDEX|
      |        -------------
      v              |
 ------------        |
 |READ DATA |        v
 ------------

```
These operations need to be performed at the exact time relative to each other, so often exploitation of such condition is challenging. 

##Exploitation attempt

So now we need to know what kind of data are we reading, like how is it exactly stored and how can we modify it. The data that is sent to function thorugh `ioctl` syscall is structure `snd_ctl_elem_value32`. Notice `__user` keyword which indicates that data resides in userspace memory.
```c
static int snd_ctl_elem_read_user_compat(struct snd_card *card,
					 struct snd_ctl_elem_value32 __user *data32)
{
	return ctl_elem_read_user(card, data32, &data32->value);
}
```

Inside that, when performing `ctl_elem_read_user` - the operations are:
* copy_ctl_value_from_user
* snd_ctl_elem_read
* copy_ctl_value_to_user

  Going one by one, let's look at function `copy_ctl_value_from_user`.  It takes `id` from data provided by user, searches for appropriate control using `snd_ctl_find_id` and reads type of data stored in the control. Then all the data is copied from user structure into target control.

Function `snd_ctl_elem_read` gets appropriate control using again `snd_ctl_find_id` and calls functions which will read data with `kctl->get` where `kctl` is our control.
```c
...
	if (!ret)
		ret = kctl->get(kctl, control);
...
```

`copy_ctl_value_to_user` basically copies data from the `kctl` obj into userland, the reverse of `copy_ctl_value_from_user`. 

The easiest way to exploit race condition that we have is creating Use After Free primitive - by freeing target object and performing operation on the freed one. 

There exists a funcitonality of freeing `kcontrols` - by sending command `SNDRV_CTL_IOCTL_ELEM_REPLACE32` to `ioctl`. While we are at it, we can also list all currently available `kcontrols` using command `SNDRV_CTL_IOCTL_ELEM_LIST32`.
List of `kcontrols` looks like this in my case.

![image](https://github.com/vido4/Linux-research/assets/5321740/d47a9a72-fcef-4690-9491-cbe704704669)

Command `SNDRV_CTL_IOCTL_ELEM_REPLACE32` expects proper structure `snd_ctl_elem_info32` to be sent as a parameter. So we need to replicate them from kernel sources. 

Requires structures are 
```c
#define SNDRV_CTL_ELEM_ID_NAME_MAXLEN   44
#define SNDRV_CTL_ELEM_TYPE_INTEGER64   6 /* 64-bit integer type */

typedef int snd_ctl_elem_iface_t;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

struct snd_ctl_elem_id {
    unsigned int numid;         /* numeric identifier, zero = invalid */
    snd_ctl_elem_iface_t iface; /* interface identifier */
    unsigned int device;                /* device/client number */
    unsigned int subdevice;             /* subdevice (substream) number */
    unsigned char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];          /* ASCII name of item */
    unsigned int index;         /* index of item */
};

struct snd_ctl_elem_info32 {
    struct snd_ctl_elem_id id; // the size of struct is same
    s32 type;
    u32 access;
    u32 count;
    s32 owner;
    union {
        struct {
            s32 min;
            s32 max;
            s32 step;
        } integer;
        struct {
            u64 min;
            u64 max;
            u64 step;
        } integer64;
        struct {
            u32 items;          //Number of name items
            u32 item;
            char name[64];
            u64 names_ptr;      //Userland ptr to names table in manner: [NAME\x00NAME\x00...]
            u32 names_length;  //length of all names buffer, max 64K
        } enumerated;
        unsigned char reserved[128];
    } value;
    unsigned char reserved[64];
} __attribute__((packed));

```

From these, we are basically required to fill only fields below
```c
struct snd_ctl_elem_info32 userinfo;
...
userinfo.owner = 0;
userinfo.count = 1; //has to be over 0
userinfo.type = SNDRV_CTL_ELEM_TYPE_INTEGER64; //Simplest type 
userinfo.id.numid = free_id;


sprintf(name, "PWN%04x", free_id);
strncpy(userinfo.id.name, name, strlen(name) + 1);
```

However, attempting to call `replace` on any of existing kcontrols yields error. That is because, there is a bit defined for every kcontrol indicating whether it is user space or kernel element
```c
#define SNDRV_CTL_ELEM_ACCESS_USER		(1<<29) /* user space element */
```
It is then checked when being removed
```c
static int snd_ctl_remove_user_ctl(structsnd_ctl_file *file,
				   structsnd_ctl_elem_id *id)
{
	structsnd_card *card =file->card;
	structsnd_kcontrol *kctl;
	int idx, ret;

down_write(&card->controls_rwsem);
kctl = snd_ctl_find_id(card, id);
	if (kctl == NULL) {
		ret = -ENOENT;
		goto error;
	}
	if (!(kctl->vd[0].access &SNDRV_CTL_ELEM_ACCESS_USER)) { !!!
		ret = -EINVAL;
		goto error;
	}
	for (idx = 0; idx < kctl->count; idx++)
		if (kctl->vd[idx].owner != NULL &&kctl->vd[idx].owner !=file) {
			ret = -EBUSY;
			goto error;
		}
	ret = snd_ctl_remove(card,kctl);
error:
up_write(&card->controls_rwsem);
	return ret;
}
```

Fortunately, we can also create our own kcontrols with command `SNDRV_CTL_IOCTL_ELEM_ADD32`.

That way, when we call replace on it, it will work properly.

While calling replace, the new kcontrol id will be calculated as `card->last_numid + 1` It is annoying to continuously keep track of last id - so we can use other behaviour of function `snd_ctl_find_id`. Whenever `id` is equal to 0, hash is calculated using name and other subfields and is used as a key for searching proper kcontrols. That way, performing read with `id` set to 0 but proper `name` fiels will reach to our `kcontrol` every time!

Combining all these steps above, we can trigger the vulnerability with outlined steps:
* Create user-controlled kcontrol with `SNDRV_CTL_IOCTL_ELEM_ADD32`
* Create separate thread that continuously deletes the kcontrol with `SNDRV_CTL_IOCTL_ELEM_REPLACE32`
* In main thread, continuously read created kcontrol with `SNDRV_CTL_IOCTL_ELEM_READ32`

Because of lack of locking in `SNDRV_CTL_IOCTL_ELEM_READ32` there will be a collision when we deleted the `kcontrol` in the `replace` step, but are reading from it by dereferencing deleted `kcontrol` and calling its `->get()` function. 
![image](https://github.com/vido4/Linux-research/assets/5321740/7be48931-f7a4-4e90-9a7f-700e6dc4f556)

## What's next?

At this step I wondered how could I stabilize the race. In the setup I've done, it takes at least few seconds until we properly win the race and crash the kernel. At this point, we should spray the kmalloc-heap of the same size with victim objects between when `kcontrol` is created and `read` function is executed. However without any prior leaks and immediate dereferencing of freed pointer, exploitation of this setup seems pretty hard. There are also no reads from userland so we cannot abuse `FUSE` or `userfaultfd` techniques to extend the race window for properly setting up the heap. As it is just an exercise and vulnerability is already fixed, I decided to stop here and take on exploiting some other bugs in kernel.

Code in repo is typical write-and-forget exploit style, so it is low-quality code, hoping it is at least somehow readable. 
