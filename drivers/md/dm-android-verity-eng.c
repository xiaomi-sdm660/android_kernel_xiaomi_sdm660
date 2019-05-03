/*
 * Copyright (C) 2015 Google, Inc.
 * Copyright (C) 2019 Tyler Nijmeh <tylernij@gmail.com>.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/mount.h>

#include "dm-verity.h"
#include "dm-android-verity-eng.h"

static int android_verity_eng_ctr(struct dm_target *ti, unsigned argc, char **argv);

static struct target_type android_verity_eng_target = {
	.name                   = "android-verity",
	.version                = {1, 0, 0},
	.module                 = THIS_MODULE,
	.ctr                    = android_verity_eng_ctr,
	.dtr                    = verity_dtr,
	.map                    = verity_map,
	.status                 = verity_status,
	.prepare_ioctl          = verity_prepare_ioctl,
	.iterate_devices        = verity_iterate_devices,
	.io_hints               = verity_io_hints,
};

static int find_size(dev_t dev, u64 *device_size)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_dev(dev, FMODE_READ, NULL);

	if (IS_ERR_OR_NULL(bdev))
		return PTR_ERR(bdev);

	*device_size = i_size_read(bdev->bd_inode);
	*device_size >>= SECTOR_SHIFT;
	blkdev_put(bdev, FMODE_READ);

	return 0;
}

static int add_as_linear_device(struct dm_target *ti, char *dev)
{
	char *linear_table_args[DM_LINEAR_ARGS] = {dev,
					DM_LINEAR_TARGET_OFFSET};

	android_verity_eng_target.dtr = dm_linear_dtr,
	android_verity_eng_target.map = dm_linear_map,
	android_verity_eng_target.status = dm_linear_status,
	android_verity_eng_target.prepare_ioctl = dm_linear_prepare_ioctl,
	android_verity_eng_target.iterate_devices = dm_linear_iterate_devices,
	android_verity_eng_target.io_hints = NULL;
	set_disk_ro(dm_disk(dm_table_get_md(ti->table)), 0);

	return dm_linear_ctr(ti, DM_LINEAR_ARGS, linear_table_args);
}

static int create_linear_device(struct dm_target *ti, dev_t dev,
				char *target_device)
{
	u64 device_size = 0;
	int err = find_size(dev, &device_size);

	if (err)
		return err;

	ti->len = device_size;
	err = add_as_linear_device(ti, target_device);

	if (err)
		return err;

	return 0;
}

static int android_verity_eng_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	dev_t uninitialized_var(dev);
	char *target_device;

	target_device = argv[0];
	dev = name_to_dev_t(target_device);

	if (!dev)
		return -EINVAL;

	return create_linear_device(ti, dev, target_device);
}

static int __init dm_android_verity_eng_init(void)
{
	return dm_register_target(&android_verity_eng_target);
}

static void __exit dm_android_verity_eng_exit(void)
{
	dm_unregister_target(&android_verity_eng_target);
}

module_init(dm_android_verity_eng_init);
module_exit(dm_android_verity_eng_exit);
