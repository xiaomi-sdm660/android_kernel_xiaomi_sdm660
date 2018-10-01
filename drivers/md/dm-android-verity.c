/*
 * Copyright (C) 2015 Google, Inc.
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

#include <linux/buffer_head.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/device-mapper.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/setup.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <crypto/sha.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>

#include "dm-verity.h"
#include "dm-android-verity.h"

static bool target_added;
static bool verity_enabled = true;
static struct dentry *debug_dir;
static int android_verity_ctr(struct dm_target *ti, unsigned argc, char **argv);

static struct target_type android_verity_target = {
	.name                   = "android-verity",
	.version                = {1, 0, 0},
	.module                 = THIS_MODULE,
	.ctr                    = android_verity_ctr,
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
	if (IS_ERR_OR_NULL(bdev)) {
		DMERR("blkdev_get_by_dev failed");
		return PTR_ERR(bdev);
	}

	*device_size = i_size_read(bdev->bd_inode);
	*device_size >>= SECTOR_SHIFT;

	DMINFO("blkdev size in sectors: %llu", *device_size);
	blkdev_put(bdev, FMODE_READ);
	return 0;
}

static int add_as_linear_device(struct dm_target *ti, char *dev)
{
	/*Move to linear mapping defines*/
	char *linear_table_args[DM_LINEAR_ARGS] = {dev,
					DM_LINEAR_TARGET_OFFSET};
	int err = 0;

	android_verity_target.dtr = dm_linear_dtr,
	android_verity_target.map = dm_linear_map,
	android_verity_target.status = dm_linear_status,
	android_verity_target.prepare_ioctl = dm_linear_prepare_ioctl,
	android_verity_target.iterate_devices = dm_linear_iterate_devices,
	android_verity_target.io_hints = NULL;

	set_disk_ro(dm_disk(dm_table_get_md(ti->table)), 0);

	err = dm_linear_ctr(ti, DM_LINEAR_ARGS, linear_table_args);

	if (!err) {
		DMINFO("Added android-verity as a linear target");
		target_added = true;
	} else
		DMERR("Failed to add android-verity as linear target");

	return err;
}

static int create_linear_device(struct dm_target *ti, dev_t dev,
				char *target_device)
{
	u64 device_size = 0;
	int err = find_size(dev, &device_size);

	if (err) {
		DMERR("error finding bdev size");
		return err;
	}

	ti->len = device_size;
	err = add_as_linear_device(ti, target_device);
	if (err) {
		return err;
	}
	verity_enabled = false;
	return 0;
}

/*
 * Target parameters:
 *	<key id>	Key id of the public key in the system keyring.
 *			Verity metadata's signature would be verified against
 *			this. If the key id contains spaces, replace them
 *			with '#'.
 *	<block device>	The block device for which dm-verity is being setup.
 */
static int android_verity_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	dev_t uninitialized_var(dev);
	char *target_device;
	/* One for specifying number of opt args and one for mode */
	struct fec_header uninitialized_var(fec);
	struct fec_ecc_metadata uninitialized_var(ecc);

	if (argc != 1 && argc != 2) {
		DMERR("Incorrect number of arguments");
		return -EINVAL;
	}

	target_device = argv[0];
	
	dev = name_to_dev_t(target_device);
	if (!dev) {
		DMERR("no dev found for %s", target_device);
		return -EINVAL;
	}

	return create_linear_device(ti, dev, target_device);
}

static int __init dm_android_verity_init(void)
{
	int r;
	struct dentry *file;

	r = dm_register_target(&android_verity_target);
	if (r < 0)
		DMERR("register failed %d", r);

	/* Tracks the status of the last added target */
	debug_dir = debugfs_create_dir("android_verity", NULL);

	if (IS_ERR_OR_NULL(debug_dir)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		goto end;
	}

	file = debugfs_create_bool("target_added", S_IRUGO, debug_dir,
				&target_added);

	if (IS_ERR_OR_NULL(file)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		debugfs_remove_recursive(debug_dir);
		goto end;
	}

	file = debugfs_create_bool("verity_enabled", S_IRUGO, debug_dir,
				&verity_enabled);

	if (IS_ERR_OR_NULL(file)) {
		DMERR("Cannot create android_verity debugfs directory: %ld",
			PTR_ERR(debug_dir));
		debugfs_remove_recursive(debug_dir);
	}

end:
	return r;
}

static void __exit dm_android_verity_exit(void)
{
	if (!IS_ERR_OR_NULL(debug_dir))
		debugfs_remove_recursive(debug_dir);

	dm_unregister_target(&android_verity_target);
}

module_init(dm_android_verity_init);
module_exit(dm_android_verity_exit);
