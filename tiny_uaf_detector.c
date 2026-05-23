#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "uaf_detector.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Dev");
MODULE_DESCRIPTION("Tiny UAF Detector");
MODULE_VERSION("1.0");

static struct uaf_object *demo_obj;

/* ========================================================= */

static int __init tiny_uaf_init(void)
{
    pr_info("[UAF] init\n");

    if (uaf_detector_init_core())
        return -ENOMEM;

    demo_obj = allocate_obj(1, "demo");
    if (!demo_obj)
        return -ENOMEM;

    access_object(demo_obj);

    free_object(demo_obj);

    /* safe check instead of real UAF crash */
    if (is_object_freed(demo_obj))
        pr_alert("[UAF DETECTED]\n");

    return 0;
}

/* ========================================================= */

static void __exit tiny_uaf_exit(void)
{
    pr_info("[UAF] exit\n");
    uaf_detector_exit_core();
}

module_init(tiny_uaf_init);
module_exit(tiny_uaf_exit);
