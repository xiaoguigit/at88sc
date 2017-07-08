#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe2630d0, "module_layout" },
	{ 0x37a0cba, "kfree" },
	{ 0xfe990052, "gpio_free" },
	{ 0x3b05df25, "malloc_sizes" },
	{ 0x7485e15e, "unregister_chrdev_region" },
	{ 0x93e5a328, "cdev_del" },
	{ 0xa06def1c, "class_destroy" },
	{ 0x3e74c3ee, "device_destroy" },
	{ 0x47229b5c, "gpio_request" },
	{ 0x18cbf17a, "device_create" },
	{ 0x84752b75, "__class_create" },
	{ 0x797b39b8, "cdev_add" },
	{ 0xb0544130, "cdev_init" },
	{ 0x29537c9e, "alloc_chrdev_region" },
	{ 0xd8e484f0, "register_chrdev_region" },
	{ 0x3d22b4f3, "kmem_cache_alloc_trace" },
	{ 0xfa2a45e, "__memzero" },
	{ 0xfbc74f64, "__copy_from_user" },
	{ 0x71c90087, "memcmp" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x6c8d5ae8, "__gpio_get_value" },
	{ 0x65d6d0f0, "gpio_direction_input" },
	{ 0x8e865d3c, "arm_delay_ops" },
	{ 0x432fd7f6, "__gpio_set_value" },
	{ 0xa8f59416, "gpio_direction_output" },
	{ 0x27e1a049, "printk" },
	{ 0x2e5810c6, "__aeabi_unwind_cpp_pr1" },
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "261E03CDA33CEA52A6EF2E1");
