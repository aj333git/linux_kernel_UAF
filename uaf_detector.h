#ifndef _UAF_DETECTOR_H
#define _UAF_DETECTOR_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/types.h>

#define CANARY_VALUE 0xDEADBEEF
#define OBJECT_NAME  32

struct uaf_object {
    u32 canary_start;
    int id;
    char name[OBJECT_NAME];
    bool freed;
    struct rcu_head rcu;
    struct list_head list;
    u32 canary_end;
};

/* API */
int uaf_detector_init_core(void);
void uaf_detector_exit_core(void);

struct uaf_object *allocate_obj(int id, const char *name);
void free_object(struct uaf_object *obj);
void access_object(struct uaf_object *obj);

bool is_object_freed(struct uaf_object *obj);

#endif
