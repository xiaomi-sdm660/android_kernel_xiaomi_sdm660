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

#ifndef DM_ANDROID_VERITY_ENG_H
#define DM_ANDROID_VERITY_ENG_H

#define DM_LINEAR_ARGS 2
#define DM_LINEAR_TARGET_OFFSET "0"

extern void dm_linear_dtr(struct dm_target *ti);
extern int dm_linear_map(struct dm_target *ti, struct bio *bio);
extern void dm_linear_status(struct dm_target *ti, status_type_t type,
			unsigned status_flags, char *result, unsigned maxlen);
extern int dm_linear_prepare_ioctl(struct dm_target *ti,
                struct block_device **bdev, fmode_t *mode);
extern int dm_linear_iterate_devices(struct dm_target *ti,
			iterate_devices_callout_fn fn, void *data);
extern int dm_linear_ctr(struct dm_target *ti, unsigned int argc, char **argv);
#endif /* DM_ANDROID_VERITY_ENG_H */
