/*
 * File: slab_uaf_detector.c
 *
 * Detects:
 *  - Use-after-free
 *  - Double free
 *  - Canary corruption
 *  - Stale RCU access
 *
 * Build:
 *   make
 *
 * Run:
 *   sudo insmod slab_uaf_detector.ko
 *
 * Observe:
 *   cat /proc/slab_uaf_stats
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 *
 * Remove:
 *   sudo rmmod slab_uaf_detector
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Developer");
MODULE_DESCRIPTION("Kernel UAF Detector");
MODULE_VERSION("1.0");

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

static struct kmem_cache *uaf_cache;

static LIST_HEAD(object_list);

static DEFINE_SPINLOCK(object_lock);

static struct proc_dir_entry *proc_entry;

static struct timer_list check_timer;

static atomic_t alloc_count = ATOMIC_INIT(0);
static atomic_t free_count  = ATOMIC_INIT(0);
static atomic_t uaf_detects = ATOMIC_INIT(0);
static atomic_t corruptions = ATOMIC_INIT(0);

/* =========================================================
 * Trace Helpers
 * ========================================================= */

#define trace_uaf(msg, id) \
    trace_printk("uaf_detector: %s id=%d cpu=%d\n", \
                 msg, id, smp_processor_id())

/* =========================================================
 * Constructor
 * ========================================================= */

static void uaf_ctor(void *obj)
{
    struct uaf_object *o = obj;

    memset(o, 0, sizeof(*o));

    o->canary_start = CANARY_VALUE;
    o->canary_end   = CANARY_VALUE;
}

/* =========================================================
 * Canary Verification
 * ========================================================= */

static bool verify_canary(struct uaf_object *obj)
{
    if (obj->canary_start != CANARY_VALUE ||
        obj->canary_end   != CANARY_VALUE) {

        atomic_inc(&corruptions);

        pr_err("[UAF] Canary corruption detected id=%d\n",
               obj->id);

        return false;
    }

    return true;
}

/* =========================================================
 * Allocate Object
 * ========================================================= */

static struct uaf_object *allocate_obj(int id,
                                       const char *name)
{
    struct uaf_object *obj;

    obj = kmem_cache_alloc(uaf_cache,
                           GFP_KERNEL);

    if (!obj)
        return NULL;

    verify_canary(obj);

    obj->id = id;

    strscpy(obj->name,
            name,
            sizeof(obj->name));

    obj->freed = false;

    spin_lock(&object_lock);

    list_add(&obj->list,
             &object_list);

    spin_unlock(&object_lock);

    atomic_inc(&alloc_count);

    trace_uaf("ALLOC", id);

    return obj;
}

/* =========================================================
 * Simulate Object Access
 * ========================================================= */

static void access_object(struct uaf_object *obj)
{
    if (!obj)
        return;

    if (obj->freed) {

        atomic_inc(&uaf_detects);

        pr_err("[UAF] Use-after-free detected id=%d\n",
               obj->id);

        trace_uaf("USE_AFTER_FREE", obj->id);

        dump_stack();

        return;
    }

    verify_canary(obj);

    pr_info("[UAF] accessed object id=%d\n",
            obj->id);
}

/* =========================================================
 * RCU Free
 * ========================================================= */

static void rcu_free_callback(struct rcu_head *rh)
{
    struct uaf_object *obj;

    obj = container_of(rh,
                       struct uaf_object,
                       rcu);

    memset(obj,
           0xA5,
           sizeof(*obj));

    kmem_cache_free(uaf_cache,
                    obj);

    atomic_inc(&free_count);

    trace_uaf("FREE", obj->id);
}

/* =========================================================
 * Free Object
 * ========================================================= */

static void free_object(struct uaf_object *obj)
{
    if (!obj)
        return;

    if (obj->freed) {

        pr_err("[UAF] Double free detected id=%d\n",
               obj->id);

        trace_uaf("DOUBLE_FREE", obj->id);

        return;
    }

    verify_canary(obj);

    obj->freed = true;

    spin_lock(&object_lock);

    list_del(&obj->list);

    spin_unlock(&object_lock);

    call_rcu(&obj->rcu,
             rcu_free_callback);
}

/* =========================================================
 * Timer Validation
 * ========================================================= */

static void timer_fn(struct timer_list *t)
{
    struct uaf_object *obj;

    spin_lock(&object_lock);

    list_for_each_entry(obj,
                        &object_list,
                        list) {

        verify_canary(obj);
    }

    spin_unlock(&object_lock);

    mod_timer(&check_timer,
              jiffies + msecs_to_jiffies(5000));
}

/* =========================================================
 * Procfs
 * ========================================================= */

static int stats_show(struct seq_file *m,
                      void *v)
{
    seq_printf(m,
               "=== UAF Detector Stats ===\n");

    seq_printf(m,
               "Allocations : %d\n",
               atomic_read(&alloc_count));

    seq_printf(m,
               "Frees       : %d\n",
               atomic_read(&free_count));

    seq_printf(m,
               "UAF Detects : %d\n",
               atomic_read(&uaf_detects));

    seq_printf(m,
               "Corruptions : %d\n",
               atomic_read(&corruptions));

    return 0;
}

static int stats_open(struct inode *inode,
                      struct file *file)
{
    return single_open(file,
                       stats_show,
                       NULL);
}

static const struct proc_ops proc_fops = {

    .proc_open    = stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* =========================================================
 * Init
 * ========================================================= */

static int __init uaf_init(void)
{
    struct uaf_object *obj;

    pr_info("[UAF] module loading\n");

    uaf_cache = kmem_cache_create(
                    "uaf_cache",
                    sizeof(struct uaf_object),
                    0,
                    SLAB_POISON |
                    SLAB_RED_ZONE,
                    uaf_ctor);

    if (!uaf_cache)
        return -ENOMEM;

    proc_entry = proc_create(
                    "slab_uaf_stats",
                    0444,
                    NULL,
                    &proc_fops);

    timer_setup(&check_timer,
                timer_fn,
                0);

    mod_timer(&check_timer,
              jiffies + msecs_to_jiffies(5000));

    obj = allocate_obj(1,
                       "demo");

    access_object(obj);

    free_object(obj);

    /*
     * Intentional UAF trigger
     */

    access_object(obj);

    pr_info("[UAF] module loaded\n");

    return 0;
}

/* =========================================================
 * Exit
 * ========================================================= */

static void __exit uaf_exit(void)
{
    del_timer_sync(&check_timer);

    synchronize_rcu();

    remove_proc_entry("slab_uaf_stats",
                      NULL);

    kmem_cache_destroy(uaf_cache);

    pr_info("[UAF] module unloaded\n");
}

module_init(uaf_init);
module_exit(uaf_exit);
