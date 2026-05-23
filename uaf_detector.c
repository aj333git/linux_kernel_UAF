#include "uaf_detector.h"

static LIST_HEAD(object_list);
static DEFINE_SPINLOCK(object_lock);

static struct kmem_cache *uaf_cache;

/* counters */
static atomic_t alloc_count = ATOMIC_INIT(0);
static atomic_t free_count  = ATOMIC_INIT(0);
static atomic_t uaf_detects = ATOMIC_INIT(0);
static atomic_t corruptions = ATOMIC_INIT(0);

/* ========================================================= */

static void uaf_ctor(void *obj)
{
    struct uaf_object *o = obj;

    memset(o, 0, sizeof(*o));
    o->canary_start = CANARY_VALUE;
    o->canary_end   = CANARY_VALUE;
}

/* ========================================================= */

static bool verify_canary(struct uaf_object *obj)
{
    if (!obj)
        return false;

    if (obj->canary_start != CANARY_VALUE ||
        obj->canary_end   != CANARY_VALUE) {

        atomic_inc(&corruptions);
        pr_err("[UAF] CANARY CORRUPTION id=%d\n", obj->id);
        return false;
    }

    return true;
}

/* ========================================================= */

bool is_object_freed(struct uaf_object *obj)
{
    return obj && obj->freed;
}

/* ========================================================= */

struct uaf_object *allocate_obj(int id, const char *name)
{
    struct uaf_object *obj;

    obj = kmem_cache_alloc(uaf_cache, GFP_KERNEL);
    if (!obj)
        return NULL;

    memset(obj, 0, sizeof(*obj));
    uaf_ctor(obj);

    obj->id = id;
    obj->freed = false;

    strscpy(obj->name, name, sizeof(obj->name));

    spin_lock(&object_lock);
    list_add(&obj->list, &object_list);
    spin_unlock(&object_lock);

    atomic_inc(&alloc_count);

    pr_info("[UAF] ALLOC id=%d\n", id);
    return obj;
}

/* ========================================================= */

void access_object(struct uaf_object *obj)
{
    if (!obj)
        return;

    if (obj->freed) {
        atomic_inc(&uaf_detects);
        pr_err("[UAF] USE-AFTER-FREE id=%d\n", obj->id);
        dump_stack();
        return;
    }

    verify_canary(obj);
    pr_info("[UAF] ACCESS id=%d\n", obj->id);
}

/* ========================================================= */

void free_object(struct uaf_object *obj)
{
    if (!obj)
        return;

    if (obj->freed) {
        pr_err("[UAF] DOUBLE FREE id=%d\n", obj->id);
        return;
    }

    obj->freed = true;

    spin_lock(&object_lock);
    list_del(&obj->list);
    spin_unlock(&object_lock);

    kmem_cache_free(uaf_cache, obj);

    atomic_inc(&free_count);

    pr_info("[UAF] FREE id=%d\n", obj->id);
}

/* ========================================================= */

int uaf_detector_init_core(void)
{
    pr_info("[UAF] core init\n");

    uaf_cache = kmem_cache_create(
        "uaf_cache",
        sizeof(struct uaf_object),
        0,
        SLAB_POISON | SLAB_RED_ZONE,
        uaf_ctor
    );

    if (!uaf_cache)
        return -ENOMEM;

    return 0;
}

/* ========================================================= */

void uaf_detector_exit_core(void)
{
    kmem_cache_destroy(uaf_cache);
    pr_info("[UAF] core exit\n");
}
