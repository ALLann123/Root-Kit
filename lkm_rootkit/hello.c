#include <linux/module.h>
#include <linux/kernel.h>

//initialize the function

static int startup(void)
{
	printk(KERN_NOTICE "Hello, Kernel reporting for duty\n");
	return 0;
}

//cleanup funtion
static void shutdown(void)
{
	printk(KERN_NOTICE "Bye,bye\n");
}

//specify the initialization and call back function
module_init(startup);
module_exit(shutdown);

MODULE_LICENSE("GPL");
