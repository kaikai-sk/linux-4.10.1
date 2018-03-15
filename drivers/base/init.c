/*
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 *
 * This file is released under the GPLv2
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/memory.h>
#include <linux/of.h>

#include "base.h"

/**
 * driver_init - initialize driver model.
 *
 * Call the driver model init functions to initialize their
 * subsystems. Called early from init/main.c.
 */
void __init driver_init(void)
{
	/* These are the core pieces */
	//初始化devtmpfs文件系统，驱动核心设备将在这个文件系统中添加它们的设备节点。  
	devtmpfs_init();
	/* 初始化驱动模型中的部分子系统和kobject： 
	   devices 
	   dev 
	   dev/block 
	   dev/char 
	*/  
	devices_init();
	//初始化驱动模型中的bus子系统  
	buses_init();
	//初始化驱动模型中的class子系统  
	classes_init();
	//1.初始化驱动模型中的firmware子系统  
	firmware_init();
	//初始化驱动模型中的hypervisor子系统  
	hypervisor_init();

	/* These are also core pieces, but must come after the
	 * core core pieces.

	  这些也是核心部件, 但是必须在以上核心中的核心部件之后调用。 
	 */
	//初始化驱动模型中的bus/platform子系统  
	platform_bus_init();
	//初始化驱动模型中的devices/system/cpu子系统  
	cpu_dev_init();
	//初始化驱动模型中的devices/system/memory子系统  
	memory_dev_init();
	container_dev_init();
	of_core_init();
}
