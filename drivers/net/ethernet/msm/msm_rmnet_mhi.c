/* Copyright (c) 2014-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
/*
 * MHI RMNET Network interface
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/msm_rmnet.h>
#include <linux/if_arp.h>
#include <linux/dma-mapping.h>
#include <linux/msm_mhi.h>
#include <linux/debugfs.h>
#include <linux/ipc_logging.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/of_device.h>
#include <linux/rtnetlink.h>

#define RMNET_MHI_DRIVER_NAME "rmnet_mhi"
#define MHI_DEFAULT_MTU        8000
#define MHI_MAX_MRU            0xFFFF
#define MHI_NAPI_WEIGHT_VALUE  12
#define WATCHDOG_TIMEOUT       (30 * HZ)
#define RMNET_IPC_LOG_PAGES (100)
#define IRQ_MASKED_BIT (0)

enum DBG_LVL {
	MSG_VERBOSE = 0x1,
	MSG_INFO = 0x2,
	MSG_DBG = 0x4,
	MSG_WARNING = 0x8,
	MSG_ERROR = 0x10,
	MSG_CRITICAL = 0x20,
	MSG_reserved = 0x80000000
};

struct debug_params {
	enum DBG_LVL rmnet_msg_lvl;
	enum DBG_LVL rmnet_ipc_log_lvl;
	u64 tx_interrupts_count;
	u64 rx_interrupts_count;
	u64 tx_ring_full_count;
	u64 tx_queued_packets_count;
	u64 rx_interrupts_in_masked_irq;
	u64 rx_napi_skb_burst_min;
	u64 rx_napi_skb_burst_max;
	u64 tx_cb_skb_free_burst_min;
	u64 tx_cb_skb_free_burst_max;
	u64 rx_napi_budget_overflow;
	u64 rx_fragmentation;
};

struct __packed mhi_skb_priv {
	dma_addr_t dma_addr;
	size_t	   dma_size;
};

#define rmnet_log(rmnet_mhi_ptr, _msg_lvl, _msg, ...) do {	\
		if ((_msg_lvl) >= rmnet_mhi_ptr->debug.rmnet_msg_lvl) \
			pr_alert("[%s] " _msg, __func__, ##__VA_ARGS__);\
		if (rmnet_mhi_ptr->rmnet_ipc_log && \
		    ((_msg_lvl) >= rmnet_mhi_ptr->debug.rmnet_ipc_log_lvl)) \
			ipc_log_string(rmnet_mhi_ptr->rmnet_ipc_log, \
			       "[%s] " _msg, __func__, ##__VA_ARGS__);	\
} while (0)

struct rmnet_mhi_private {
	struct list_head	      node;
	u32                           dev_id;
	const char		      *interface_name;
	struct mhi_client_handle      *tx_client_handle;
	struct mhi_client_handle      *rx_client_handle;
	enum MHI_CLIENT_CHANNEL       tx_channel;
	enum MHI_CLIENT_CHANNEL       rx_channel;
	struct sk_buff_head           tx_buffers;
	struct sk_buff_head           rx_buffers;
	atomic_t		      rx_pool_len;
	u32			      mru;
	u32			      max_mru;
	u32			      max_mtu;
	struct napi_struct            napi;
	gfp_t                         allocation_flags;
	uint32_t                      tx_buffers_max;
	uint32_t                      rx_buffers_max;
	u32			      alloc_fail;
	u32			      tx_enabled;
	u32			      rx_enabled;
	u32			      mhi_enabled;
	struct platform_device        *pdev;
	struct net_device	      *dev;
	unsigned long		      flags;
	int			      wake_count;
	spinlock_t		      out_chan_full_lock; /* tx queue lock */
	struct sk_buff		      *frag_skb;
	struct work_struct	      alloc_work;
	/* lock to queue hardware and internal queue */
	spinlock_t		      alloc_lock;
	void			      *rmnet_ipc_log;
	rwlock_t		      pm_lock; /* state change lock */
	struct debug_params	      debug;
	struct dentry		      *dentry;
};

static LIST_HEAD(rmnet_mhi_ctxt_list);
static struct platform_driver rmnet_mhi_driver;

static int rmnet_mhi_process_fragment(struct rmnet_mhi_private *rmnet_mhi_ptr,
				       struct sk_buff *skb, int frag)
{
	struct sk_buff *temp_skb;
	if (rmnet_mhi_ptr->frag_skb) {
		/* Merge the new skb into the old fragment */
		temp_skb = skb_copy_expand(rmnet_mhi_ptr->frag_skb,
					   0,
					   skb->len,
					   GFP_ATOMIC);
		if (!temp_skb) {
			kfree(rmnet_mhi_ptr->frag_skb);
			rmnet_mhi_ptr->frag_skb = NULL;
			return -ENOMEM;
		}
		dev_kfree_skb_any(rmnet_mhi_ptr->frag_skb);
		rmnet_mhi_ptr->frag_skb = temp_skb;
		memcpy(skb_put(rmnet_mhi_ptr->frag_skb, skb->len),
			skb->data,
			skb->len);
		dev_kfree_skb_any(skb);
		if (!frag) {
			/* Last fragmented piece was received, ship it */
			netif_receive_skb(rmnet_mhi_ptr->frag_skb);
			rmnet_mhi_ptr->frag_skb = NULL;
		}
	} else {
		if (frag) {
			/* This is the first fragment */
			rmnet_mhi_ptr->frag_skb = skb;
			rmnet_mhi_ptr->debug.rx_fragmentation++;
		} else {
			netif_receive_skb(skb);
		}
	}
	return 0;
}
static void rmnet_mhi_internal_clean_unmap_buffers(struct net_device *dev,
						   struct sk_buff_head *queue,
						   enum dma_data_direction dir)
{
	struct mhi_skb_priv *skb_priv;
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Entered\n");
	while (!skb_queue_empty(queue)) {
		struct sk_buff *skb = skb_dequeue(queue);
		skb_priv = (struct mhi_skb_priv *)(skb->cb);
		if (skb != 0) {
			kfree_skb(skb);
		}
	}
	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Exited\n");
}

static __be16 rmnet_mhi_ip_type_trans(struct sk_buff *skb)
{
	__be16 protocol = 0;

	/* Determine L3 protocol */
	switch (skb->data[0] & 0xf0) {
	case 0x40:
		protocol = htons(ETH_P_IP);
		break;
	case 0x60:
		protocol = htons(ETH_P_IPV6);
		break;
	default:
		/* Default is QMAP */
		protocol = htons(ETH_P_MAP);
		break;
	}
	return protocol;
}

static int rmnet_alloc_rx(struct rmnet_mhi_private *rmnet_mhi_ptr,
			  gfp_t alloc_flags)
{
	u32 cur_mru = rmnet_mhi_ptr->mru;
	struct mhi_skb_priv *skb_priv;
	int ret;
	struct sk_buff *skb;

	while (atomic_read(&rmnet_mhi_ptr->rx_pool_len) <
	       rmnet_mhi_ptr->rx_buffers_max) {
		skb = alloc_skb(cur_mru, alloc_flags);
		if (!skb) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_INFO,
				  "SKB Alloc failed with flags:0x%x\n",
				  alloc_flags);
			return -ENOMEM;
		}
		skb_priv = (struct mhi_skb_priv *)(skb->cb);
		skb_priv->dma_size = cur_mru;
		skb_priv->dma_addr = 0;

		/* These steps must be in atomic context */
		spin_lock_bh(&rmnet_mhi_ptr->alloc_lock);

		/* It's possible by the time alloc_skb (GFP_KERNEL)
		 * returns we already called rmnet_alloc_rx
		 * in atomic context and allocated memory using
		 * GFP_ATOMIC and returned.
		 */
		if (unlikely(atomic_read(&rmnet_mhi_ptr->rx_pool_len) >=
			     rmnet_mhi_ptr->rx_buffers_max)) {
			spin_unlock_bh(&rmnet_mhi_ptr->alloc_lock);
			dev_kfree_skb_any(skb);
			return 0;
		}

		read_lock_bh(&rmnet_mhi_ptr->pm_lock);
		if (unlikely(!rmnet_mhi_ptr->mhi_enabled)) {
			rmnet_log(rmnet_mhi_ptr, MSG_INFO,
				  "!interface is disabled\n");
			dev_kfree_skb_any(skb);
			read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
			spin_unlock_bh(&rmnet_mhi_ptr->alloc_lock);
			return -EIO;
		}

		ret = mhi_queue_xfer(rmnet_mhi_ptr->rx_client_handle,
				     skb->data,
				     skb_priv->dma_size,
				     MHI_EOT);
		if (unlikely(ret != 0)) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "mhi_queue_xfer failed, error %d", ret);
			read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
			spin_unlock_bh(&rmnet_mhi_ptr->alloc_lock);
			dev_kfree_skb_any(skb);
			return ret;
		}
		skb_queue_tail(&rmnet_mhi_ptr->rx_buffers, skb);
		atomic_inc(&rmnet_mhi_ptr->rx_pool_len);
		read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
		spin_unlock_bh(&rmnet_mhi_ptr->alloc_lock);
	}

	return 0;
}

static void rmnet_mhi_alloc_work(struct work_struct *work)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr = container_of(work,
				    struct rmnet_mhi_private,
				    alloc_work);
	int ret;
	/* sleep about 1 sec and retry, that should be enough time
	 * for system to reclaim freed memory back.
	 */
	const int sleep_ms =  1000;
	int retry = 60;

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Entered\n");
	do {
		ret = rmnet_alloc_rx(rmnet_mhi_ptr,
				     rmnet_mhi_ptr->allocation_flags);
		/* sleep and try again */
		if (ret == -ENOMEM) {
			msleep(sleep_ms);
			retry--;
		}
	} while (ret == -ENOMEM && retry);

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Exit with status:%d retry:%d\n",
		  ret, retry);
}

static int rmnet_mhi_poll(struct napi_struct *napi, int budget)
{
	int received_packets = 0;
	struct net_device *dev = napi->dev;
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);
	int res = 0;
	bool should_reschedule = true;
	struct sk_buff *skb;
	struct mhi_skb_priv *skb_priv;
	int r;

	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Entered\n");

	read_lock_bh(&rmnet_mhi_ptr->pm_lock);
	if (unlikely(!rmnet_mhi_ptr->mhi_enabled)) {
		rmnet_log(rmnet_mhi_ptr, MSG_INFO, "interface is disabled!\n");
		read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
		return 0;
	}
	while (received_packets < budget) {
		struct mhi_result *result =
		      mhi_poll(rmnet_mhi_ptr->rx_client_handle);
		if (result->transaction_status == -ENOTCONN) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_INFO,
				  "Transaction status not ready, continuing\n");
			break;
		} else if (result->transaction_status != 0 &&
			   result->transaction_status != -EOVERFLOW) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "mhi_poll failed, error %d\n",
				  result->transaction_status);
			break;
		}

		/* Nothing more to read, or out of buffers in MHI layer */
		if (unlikely(!result->buf_addr || !result->bytes_xferd)) {
			should_reschedule = false;
			break;
		}

		atomic_dec(&rmnet_mhi_ptr->rx_pool_len);
		skb = skb_dequeue(&(rmnet_mhi_ptr->rx_buffers));
		if (unlikely(!skb)) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "No RX buffers to match");
			break;
		}

		skb_priv = (struct mhi_skb_priv *)(skb->cb);

		/* Setup the tail to the end of data */
		skb_put(skb, result->bytes_xferd);

		skb->dev = dev;
		skb->protocol = rmnet_mhi_ip_type_trans(skb);

		if (result->transaction_status == -EOVERFLOW)
			r = rmnet_mhi_process_fragment(rmnet_mhi_ptr, skb, 1);
		else
			r = rmnet_mhi_process_fragment(rmnet_mhi_ptr, skb, 0);
		if (r) {
			rmnet_log(rmnet_mhi_ptr, MSG_CRITICAL,
				  "Failed to process fragmented packet ret %d",
				   r);
			BUG();
		}

		/* Statistics */
		received_packets++;
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += result->bytes_xferd;

	} /* while (received_packets < budget) or any other error */
	read_unlock_bh(&rmnet_mhi_ptr->pm_lock);

	/* Queue new buffers */
	res = rmnet_alloc_rx(rmnet_mhi_ptr, GFP_ATOMIC);

	read_lock_bh(&rmnet_mhi_ptr->pm_lock);
	if (likely(rmnet_mhi_ptr->mhi_enabled)) {
		if (res == -ENOMEM) {
			rmnet_log(rmnet_mhi_ptr, MSG_INFO,
				  "out of mem, queuing bg worker\n");
			rmnet_mhi_ptr->alloc_fail++;
			schedule_work(&rmnet_mhi_ptr->alloc_work);
		}

		napi_complete(napi);

		/* We got a NULL descriptor back */
		if (!should_reschedule) {
			if (test_and_clear_bit(IRQ_MASKED_BIT,
					       &rmnet_mhi_ptr->flags))
				mhi_unmask_irq(rmnet_mhi_ptr->rx_client_handle);
			mhi_set_lpm(rmnet_mhi_ptr->rx_client_handle, true);
			rmnet_mhi_ptr->wake_count--;
		} else {
			if (received_packets == budget)
				rmnet_mhi_ptr->debug.rx_napi_budget_overflow++;
			napi_reschedule(napi);
		}

		rmnet_mhi_ptr->debug.rx_napi_skb_burst_min =
			min((u64)received_packets,
			    rmnet_mhi_ptr->debug.rx_napi_skb_burst_min);

		rmnet_mhi_ptr->debug.rx_napi_skb_burst_max =
			max((u64)received_packets,
			    rmnet_mhi_ptr->debug.rx_napi_skb_burst_max);
	}
	read_unlock_bh(&rmnet_mhi_ptr->pm_lock);

	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE,
		  "Exited, polled %d pkts\n", received_packets);
	return received_packets;
}

static int rmnet_mhi_init_inbound(struct rmnet_mhi_private *rmnet_mhi_ptr)
{
	int res;

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Entered\n");
	rmnet_mhi_ptr->tx_buffers_max = mhi_get_max_desc(
					rmnet_mhi_ptr->tx_client_handle);
	rmnet_mhi_ptr->rx_buffers_max = mhi_get_max_desc(
					rmnet_mhi_ptr->rx_client_handle);
	atomic_set(&rmnet_mhi_ptr->rx_pool_len, 0);
	res = rmnet_alloc_rx(rmnet_mhi_ptr,
			     rmnet_mhi_ptr->allocation_flags);

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Exited with %d\n", res);
	return res;
}

static void rmnet_mhi_tx_cb(struct mhi_result *result)
{
	struct net_device *dev;
	struct rmnet_mhi_private *rmnet_mhi_ptr;
	unsigned long burst_counter = 0;
	unsigned long flags, pm_flags;

	rmnet_mhi_ptr = result->user_data;
	dev = rmnet_mhi_ptr->dev;
	rmnet_mhi_ptr->debug.tx_interrupts_count++;

	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Entered\n");
	if (!result->buf_addr || !result->bytes_xferd)
		return;
	/* Free the buffers which are TX'd up to the provided address */
	while (!skb_queue_empty(&(rmnet_mhi_ptr->tx_buffers))) {
		struct sk_buff *skb =
			skb_dequeue(&(rmnet_mhi_ptr->tx_buffers));
		if (!skb) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "NULL buffer returned, error");
			break;
		} else {
			if (skb->data == result->buf_addr) {
				dev_kfree_skb_any(skb);
				break;
			}
			dev_kfree_skb_any(skb);
			burst_counter++;

			/* Update statistics */
			dev->stats.tx_packets++;
			dev->stats.tx_bytes += skb->len;

			/* The payload is expected to be the phy addr.
			   Comparing to see if it's the last skb to
			   replenish
			*/
		}
	} /* While TX queue is not empty */

	rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_min =
		min((u64)burst_counter,
		    rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_min);

	rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_max =
		max((u64)burst_counter,
		    rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_max);

	/* In case we couldn't write again, now we can! */
	read_lock_irqsave(&rmnet_mhi_ptr->pm_lock, pm_flags);
	if (likely(rmnet_mhi_ptr->mhi_enabled)) {
		spin_lock_irqsave(&rmnet_mhi_ptr->out_chan_full_lock, flags);
		rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Waking up queue\n");
		netif_wake_queue(dev);
		spin_unlock_irqrestore(&rmnet_mhi_ptr->out_chan_full_lock,
				       flags);
	}
	read_unlock_irqrestore(&rmnet_mhi_ptr->pm_lock, pm_flags);
	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Exited\n");
}

static void rmnet_mhi_rx_cb(struct mhi_result *result)
{
	struct net_device *dev;
	struct rmnet_mhi_private *rmnet_mhi_ptr;
	unsigned long flags;

	rmnet_mhi_ptr = result->user_data;
	dev = rmnet_mhi_ptr->dev;

	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Entered\n");
	rmnet_mhi_ptr->debug.rx_interrupts_count++;
	read_lock_irqsave(&rmnet_mhi_ptr->pm_lock, flags);
	if (likely(rmnet_mhi_ptr->mhi_enabled)) {
		if (napi_schedule_prep(&rmnet_mhi_ptr->napi)) {
			if (!test_and_set_bit(IRQ_MASKED_BIT,
					      &rmnet_mhi_ptr->flags))
				mhi_mask_irq(rmnet_mhi_ptr->rx_client_handle);
			mhi_set_lpm(rmnet_mhi_ptr->rx_client_handle, false);
			rmnet_mhi_ptr->wake_count++;
			__napi_schedule(&rmnet_mhi_ptr->napi);
		} else {
			rmnet_mhi_ptr->debug.rx_interrupts_in_masked_irq++;
		}
	}
	read_unlock_irqrestore(&rmnet_mhi_ptr->pm_lock, flags);
	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Exited\n");
}

static int rmnet_mhi_open(struct net_device *dev)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);

	rmnet_log(rmnet_mhi_ptr, MSG_INFO,
		  "Opened net dev interface for MHI chans %d and %d\n",
		  rmnet_mhi_ptr->tx_channel,
		  rmnet_mhi_ptr->rx_channel);

	/* tx queue may not necessarily be stopped already
	 * so stop the queue if tx path is not enabled
	 */
	if (!rmnet_mhi_ptr->tx_client_handle)
		netif_stop_queue(dev);
	else
		netif_start_queue(dev);

	/* Poll to check if any buffers are accumulated in the
	 * transport buffers
	 */
	read_lock_bh(&rmnet_mhi_ptr->pm_lock);
	if (likely(rmnet_mhi_ptr->mhi_enabled)) {
		if (napi_schedule_prep(&rmnet_mhi_ptr->napi)) {
			if (!test_and_set_bit(IRQ_MASKED_BIT,
					      &rmnet_mhi_ptr->flags)) {
				mhi_mask_irq(rmnet_mhi_ptr->rx_client_handle);
			}
			mhi_set_lpm(rmnet_mhi_ptr->rx_client_handle, false);
			rmnet_mhi_ptr->wake_count++;
			__napi_schedule(&rmnet_mhi_ptr->napi);
		} else {
			rmnet_mhi_ptr->debug.rx_interrupts_in_masked_irq++;
		}
	}
	read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
	return 0;

}

static int rmnet_mhi_disable(struct rmnet_mhi_private *rmnet_mhi_ptr)
{
	napi_disable(&(rmnet_mhi_ptr->napi));
	rmnet_mhi_ptr->rx_enabled = 0;
	rmnet_mhi_internal_clean_unmap_buffers(rmnet_mhi_ptr->dev,
					       &rmnet_mhi_ptr->rx_buffers,
					       DMA_FROM_DEVICE);
	if (test_and_clear_bit(IRQ_MASKED_BIT, &rmnet_mhi_ptr->flags))
		mhi_unmask_irq(rmnet_mhi_ptr->rx_client_handle);

	return 0;
}

static int rmnet_mhi_stop(struct net_device *dev)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr =
		*(struct rmnet_mhi_private **)netdev_priv(dev);

	netif_stop_queue(dev);
	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Entered\n");
	if (test_and_clear_bit(IRQ_MASKED_BIT, &rmnet_mhi_ptr->flags)) {
		mhi_unmask_irq(rmnet_mhi_ptr->rx_client_handle);
		rmnet_log(rmnet_mhi_ptr, MSG_ERROR,
			  "IRQ was masked, unmasking...\n");
	}
	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Exited\n");
	return 0;
}

static int rmnet_mhi_change_mtu(struct net_device *dev, int new_mtu)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);

	if (new_mtu < 0 || rmnet_mhi_ptr->max_mtu < new_mtu)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int rmnet_mhi_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);
	int res = 0;
	unsigned long flags;
	struct mhi_skb_priv *tx_priv;

	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE,
		  "Entered chan %d\n", rmnet_mhi_ptr->tx_channel);

	tx_priv = (struct mhi_skb_priv *)(skb->cb);
	tx_priv->dma_size = skb->len;
	tx_priv->dma_addr = 0;
	read_lock_bh(&rmnet_mhi_ptr->pm_lock);
	if (unlikely(!rmnet_mhi_ptr->mhi_enabled)) {
		/* Only reason interface could be disabled and we get data
		 * is due to an SSR. We do not want to stop the queue and
		 * return error. instead we will flush all the uplink packets
		 * and return successful
		 */
		res = NETDEV_TX_OK;
		dev_kfree_skb_any(skb);
		goto mhi_xmit_exit;
	}

	if (mhi_get_free_desc(rmnet_mhi_ptr->tx_client_handle) <= 0) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_VERBOSE,
			  "Stopping Queue\n");
		spin_lock_irqsave(&rmnet_mhi_ptr->out_chan_full_lock,
				  flags);
		rmnet_mhi_ptr->debug.tx_ring_full_count++;
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&rmnet_mhi_ptr->out_chan_full_lock,
				       flags);
		res = NETDEV_TX_BUSY;
		goto mhi_xmit_exit;
	}
	res = mhi_queue_xfer(rmnet_mhi_ptr->tx_client_handle,
			     skb->data,
			     skb->len,
			     MHI_EOT);

	if (res != 0) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_CRITICAL,
			  "Failed to queue with reason:%d\n",
			  res);
		spin_lock_irqsave(&rmnet_mhi_ptr->out_chan_full_lock,
				  flags);
		netif_stop_queue(dev);
		spin_unlock_irqrestore(&rmnet_mhi_ptr->out_chan_full_lock,
				       flags);
		res = NETDEV_TX_BUSY;
		goto mhi_xmit_exit;
	}
	res = NETDEV_TX_OK;
	skb_queue_tail(&(rmnet_mhi_ptr->tx_buffers), skb);
	dev->trans_start = jiffies;
	rmnet_mhi_ptr->debug.tx_queued_packets_count++;
mhi_xmit_exit:
	read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
	rmnet_log(rmnet_mhi_ptr, MSG_VERBOSE, "Exited\n");
	return res;
}

static int rmnet_mhi_ioctl_extended(struct net_device *dev, struct ifreq *ifr)
{
	struct rmnet_ioctl_extended_s ext_cmd;
	int rc = 0;
	struct rmnet_mhi_private *rmnet_mhi_ptr =
			*(struct rmnet_mhi_private **)netdev_priv(dev);


	rc = copy_from_user(&ext_cmd, ifr->ifr_ifru.ifru_data,
			    sizeof(struct rmnet_ioctl_extended_s));

	if (rc) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_CRITICAL,
			  "copy_from_user failed ,error %d",
			  rc);
		return rc;
	}

	switch (ext_cmd.extended_ioctl) {
	case RMNET_IOCTL_SET_MRU:
		if (!ext_cmd.u.data ||
		    ext_cmd.u.data > rmnet_mhi_ptr->max_mru) {
			rmnet_log(rmnet_mhi_ptr, MSG_CRITICAL,
				  "Can't set MRU, value:%u is invalid max:%u\n",
				  ext_cmd.u.data, rmnet_mhi_ptr->max_mru);
			return -EINVAL;
		}
		rmnet_log(rmnet_mhi_ptr,
			  MSG_INFO,
			  "MRU change request to 0x%x\n",
			  ext_cmd.u.data);
		rmnet_mhi_ptr->mru = ext_cmd.u.data;
		break;
	case RMNET_IOCTL_GET_EPID:
		ext_cmd.u.data =
			mhi_get_epid(rmnet_mhi_ptr->tx_client_handle);
		break;
	case RMNET_IOCTL_GET_SUPPORTED_FEATURES:
		ext_cmd.u.data = 0;
		break;
	case RMNET_IOCTL_GET_DRIVER_NAME:
		strlcpy(ext_cmd.u.if_name, rmnet_mhi_ptr->interface_name,
			sizeof(ext_cmd.u.if_name));
		break;
	case RMNET_IOCTL_SET_SLEEP_STATE:
		read_lock_bh(&rmnet_mhi_ptr->pm_lock);
		if (rmnet_mhi_ptr->mhi_enabled &&
		    rmnet_mhi_ptr->tx_client_handle != NULL) {
			rmnet_mhi_ptr->wake_count += (ext_cmd.u.data) ? -1 : 1;
			mhi_set_lpm(rmnet_mhi_ptr->tx_client_handle,
				   ext_cmd.u.data);
		} else {
			rmnet_log(rmnet_mhi_ptr, MSG_ERROR,
				  "Cannot set LPM value, MHI is not up.\n");
			read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
			return -ENODEV;
		}
		read_unlock_bh(&rmnet_mhi_ptr->pm_lock);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	rc = copy_to_user(ifr->ifr_ifru.ifru_data, &ext_cmd,
			  sizeof(struct rmnet_ioctl_extended_s));

	if (rc)
		rmnet_log(rmnet_mhi_ptr,
			  MSG_CRITICAL,
			  "copy_to_user failed, error %d\n",
			  rc);

	return rc;
}

static int rmnet_mhi_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc = 0;
	struct rmnet_ioctl_data_s ioctl_data;

	switch (cmd) {
	case RMNET_IOCTL_SET_LLP_IP:        /* Set RAWIP protocol */
		break;
	case RMNET_IOCTL_GET_LLP:           /* Get link protocol state */
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
		    sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	case RMNET_IOCTL_GET_OPMODE:        /* Get operation mode      */
		ioctl_data.u.operation_mode = RMNET_MODE_LLP_IP;
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &ioctl_data,
		    sizeof(struct rmnet_ioctl_data_s)))
			rc = -EFAULT;
		break;
	case RMNET_IOCTL_SET_QOS_ENABLE:
		rc = -EINVAL;
		break;
	case RMNET_IOCTL_SET_QOS_DISABLE:
		rc = 0;
		break;
	case RMNET_IOCTL_OPEN:
	case RMNET_IOCTL_CLOSE:
		/* We just ignore them and return success */
		rc = 0;
		break;
	case RMNET_IOCTL_EXTENDED:
		rc = rmnet_mhi_ioctl_extended(dev, ifr);
		break;
	default:
		/* Don't fail any IOCTL right now */
		rc = 0;
		break;
	}

	return rc;
}

static const struct net_device_ops rmnet_mhi_ops_ip = {
	.ndo_open = rmnet_mhi_open,
	.ndo_stop = rmnet_mhi_stop,
	.ndo_start_xmit = rmnet_mhi_xmit,
	.ndo_do_ioctl = rmnet_mhi_ioctl,
	.ndo_change_mtu = rmnet_mhi_change_mtu,
	.ndo_set_mac_address = 0,
	.ndo_validate_addr = 0,
};

static void rmnet_mhi_setup(struct net_device *dev)
{
	dev->netdev_ops = &rmnet_mhi_ops_ip;
	ether_setup(dev);

	/* set this after calling ether_setup */
	dev->header_ops = 0;  /* No header */
	dev->type = ARPHRD_RAWIP;
	dev->hard_header_len = 0;
	dev->mtu = MHI_DEFAULT_MTU;
	dev->addr_len = 0;
	dev->flags &= ~(IFF_BROADCAST | IFF_MULTICAST);
	dev->watchdog_timeo = WATCHDOG_TIMEOUT;
}

static int rmnet_mhi_enable_iface(struct rmnet_mhi_private *rmnet_mhi_ptr)
{
	int ret = 0;
	struct rmnet_mhi_private **rmnet_mhi_ctxt = NULL;
	int r = 0;
	char ifalias[IFALIASZ];
	char ifname[IFNAMSIZ];
	struct mhi_client_handle *client_handle = NULL;

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Entered.\n");

	rmnet_mhi_ptr->debug.tx_interrupts_count = 0;
	rmnet_mhi_ptr->debug.rx_interrupts_count = 0;
	rmnet_mhi_ptr->debug.rx_interrupts_in_masked_irq = 0;
	rmnet_mhi_ptr->debug.rx_napi_skb_burst_min = 0;
	rmnet_mhi_ptr->debug.rx_napi_skb_burst_max = 0;
	rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_min = 0;
	rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_max = 0;
	rmnet_mhi_ptr->debug.tx_ring_full_count = 0;
	rmnet_mhi_ptr->debug.tx_queued_packets_count = 0;
	rmnet_mhi_ptr->debug.rx_napi_budget_overflow = 0;
	rmnet_mhi_ptr->debug.rx_napi_skb_burst_min = UINT_MAX;
	rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_min = UINT_MAX;

	skb_queue_head_init(&(rmnet_mhi_ptr->tx_buffers));
	skb_queue_head_init(&(rmnet_mhi_ptr->rx_buffers));

	if (rmnet_mhi_ptr->tx_client_handle != NULL) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_INFO,
			  "Opening TX channel\n");
		r = mhi_open_channel(rmnet_mhi_ptr->tx_client_handle);
		if (r != 0) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "Failed to start TX chan ret %d\n",
				  r);
			goto mhi_tx_chan_start_fail;
		}

		client_handle = rmnet_mhi_ptr->tx_client_handle;
	}
	if (rmnet_mhi_ptr->rx_client_handle != NULL) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_INFO,
			  "Opening RX channel\n");
		r = mhi_open_channel(rmnet_mhi_ptr->rx_client_handle);
		if (r != 0) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "Failed to start RX chan ret %d\n",
				  r);
			goto mhi_rx_chan_start_fail;
		}
		/* Both tx & rx client handle contain same device info */
		client_handle = rmnet_mhi_ptr->rx_client_handle;
	}

	if (!client_handle) {
		ret = -EINVAL;
		goto net_dev_alloc_fail;
	}


	if (!rmnet_mhi_ptr->dev) {
		snprintf(ifalias, sizeof(ifalias),
			 "%s_%04x_%02u.%02u.%02u_%u",
			 rmnet_mhi_ptr->interface_name,
			 client_handle->dev_id,
			 client_handle->domain,
			 client_handle->bus,
			 client_handle->slot,
			 rmnet_mhi_ptr->dev_id);

		snprintf(ifname, sizeof(ifname), "%s%%d",
			 rmnet_mhi_ptr->interface_name);

		rtnl_lock();
		rmnet_mhi_ptr->dev = alloc_netdev(
				sizeof(struct rmnet_mhi_private *),
				ifname, NET_NAME_PREDICTABLE, rmnet_mhi_setup);

		if (!rmnet_mhi_ptr->dev) {
			rmnet_log(rmnet_mhi_ptr, MSG_CRITICAL,
				  "Network device allocation failed\n");
			ret = -ENOMEM;
			goto net_dev_alloc_fail;
		}
		SET_NETDEV_DEV(rmnet_mhi_ptr->dev, &rmnet_mhi_ptr->pdev->dev);
		dev_set_alias(rmnet_mhi_ptr->dev, ifalias, strlen(ifalias));
		rmnet_mhi_ctxt = netdev_priv(rmnet_mhi_ptr->dev);
		rtnl_unlock();
		*rmnet_mhi_ctxt = rmnet_mhi_ptr;

		ret = dma_set_mask(&rmnet_mhi_ptr->dev->dev, MHI_DMA_MASK);
		if (ret)
			rmnet_mhi_ptr->allocation_flags = GFP_KERNEL;
		else
			rmnet_mhi_ptr->allocation_flags = GFP_DMA;

		netif_napi_add(rmnet_mhi_ptr->dev, &rmnet_mhi_ptr->napi,
			       rmnet_mhi_poll, MHI_NAPI_WEIGHT_VALUE);

		ret = register_netdev(rmnet_mhi_ptr->dev);
		if (ret) {
			rmnet_log(rmnet_mhi_ptr, MSG_CRITICAL,
				  "Network device registration failed\n");
			goto net_dev_reg_fail;
		}
	}

	write_lock_irq(&rmnet_mhi_ptr->pm_lock);
	rmnet_mhi_ptr->mhi_enabled = 1;
	write_unlock_irq(&rmnet_mhi_ptr->pm_lock);

	r = rmnet_mhi_init_inbound(rmnet_mhi_ptr);
	if (r) {
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "Failed to init inbound ret %d\n", r);
	}

	napi_enable(&(rmnet_mhi_ptr->napi));

	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Exited.\n");

	return 0;

net_dev_reg_fail:
	netif_napi_del(&(rmnet_mhi_ptr->napi));
	free_netdev(rmnet_mhi_ptr->dev);
net_dev_alloc_fail:
	if (rmnet_mhi_ptr->rx_client_handle) {
		mhi_close_channel(rmnet_mhi_ptr->rx_client_handle);
		rmnet_mhi_ptr->dev = NULL;
	}
mhi_rx_chan_start_fail:
	if (rmnet_mhi_ptr->tx_client_handle)
		mhi_close_channel(rmnet_mhi_ptr->tx_client_handle);
mhi_tx_chan_start_fail:
	rmnet_log(rmnet_mhi_ptr, MSG_INFO, "Exited ret %d.\n", ret);
	return ret;
}

static void rmnet_mhi_cb(struct mhi_cb_info *cb_info)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr;
	struct mhi_result *result;
	char ifalias[IFALIASZ];
	int r = 0;

	if (!cb_info || !cb_info->result) {
		pr_err("%s: Invalid data in MHI callback\n", __func__);
		return;
	}

	result = cb_info->result;
	rmnet_mhi_ptr = result->user_data;

	switch (cb_info->cb_reason) {
	case MHI_CB_MHI_DISABLED:
	case MHI_CB_MHI_SHUTDOWN:
	case MHI_CB_SYS_ERROR:
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "Got MHI_SYS_ERROR notification. Stopping stack\n");

		/* Disable interface on first notification.  Long
		 * as we set mhi_enabled = 0, we gurantee rest of
		 * driver will not touch any critical data.
		*/
		snprintf(ifalias, sizeof(ifalias), "%s", "unidentified_netdev");
		write_lock_irq(&rmnet_mhi_ptr->pm_lock);
		rmnet_mhi_ptr->mhi_enabled = 0;
		write_unlock_irq(&rmnet_mhi_ptr->pm_lock);
		/* Set unidentified_net_dev string to ifalias
		 * on error notification
		*/
		rtnl_lock();
		dev_set_alias(rmnet_mhi_ptr->dev, ifalias, strlen(ifalias));
		rtnl_unlock();

		if (cb_info->chan == rmnet_mhi_ptr->rx_channel) {
			rmnet_log(rmnet_mhi_ptr, MSG_INFO,
				  "Receive MHI_DISABLE notification for rx path\n");
			if (rmnet_mhi_ptr->dev)
				rmnet_mhi_disable(rmnet_mhi_ptr);
		} else {
			rmnet_log(rmnet_mhi_ptr, MSG_INFO,
				  "Receive MHI_DISABLE notification for tx path\n");
			rmnet_mhi_ptr->tx_enabled = 0;
			if (rmnet_mhi_ptr->dev)
				rmnet_mhi_internal_clean_unmap_buffers(
						rmnet_mhi_ptr->dev,
						&rmnet_mhi_ptr->tx_buffers,
						DMA_TO_DEVICE);
		}

		/* Remove all votes disabling low power mode */
		if (!rmnet_mhi_ptr->tx_enabled && !rmnet_mhi_ptr->rx_enabled) {
			struct mhi_client_handle *handle =
				rmnet_mhi_ptr->rx_client_handle;

			if (!handle)
				handle = rmnet_mhi_ptr->tx_client_handle;
			while (rmnet_mhi_ptr->wake_count) {
				mhi_set_lpm(handle, true);
				rmnet_mhi_ptr->wake_count--;
			}
		}
		break;
	case MHI_CB_MHI_ENABLED:
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "Got MHI_ENABLED notification. Starting stack\n");
		if (cb_info->chan == rmnet_mhi_ptr->rx_channel)
			rmnet_mhi_ptr->rx_enabled = 1;
		else
			rmnet_mhi_ptr->tx_enabled = 1;

		if ((rmnet_mhi_ptr->tx_enabled && rmnet_mhi_ptr->rx_enabled) ||
		    (rmnet_mhi_ptr->tx_enabled &&
		     !rmnet_mhi_ptr->rx_client_handle) ||
		    (rmnet_mhi_ptr->rx_enabled &&
		     !rmnet_mhi_ptr->tx_client_handle)) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_INFO,
				  "enabling iface.\n");
			r = rmnet_mhi_enable_iface(rmnet_mhi_ptr);
			if (r)
				rmnet_log(rmnet_mhi_ptr,
					  MSG_CRITICAL,
					  "Failed to enable iface for chan %d\n",
					  cb_info->chan);
			else
				rmnet_log(rmnet_mhi_ptr,
					  MSG_INFO,
					  "Enabled iface for chan %d\n",
					  cb_info->chan);
		}
		break;
	case MHI_CB_XFER:
		if (cb_info->chan == rmnet_mhi_ptr->rx_channel)
			rmnet_mhi_rx_cb(cb_info->result);
		else
			rmnet_mhi_tx_cb(cb_info->result);
		break;
	default:
		break;
	}
}

#ifdef CONFIG_DEBUG_FS
struct dentry *dentry;

static void rmnet_mhi_create_debugfs(struct rmnet_mhi_private *rmnet_mhi_ptr)
{
	char node_name[32];
	int i;
	const umode_t mode = (S_IRUSR | S_IWUSR);
	struct dentry *file;
	struct mhi_client_handle *client_handle;

	const struct {
		char *name;
		u64 *ptr;
	} debugfs_table[] = {
		{
			"tx_interrupts_count",
			&rmnet_mhi_ptr->debug.tx_interrupts_count
		},
		{
			"rx_interrupts_count",
			&rmnet_mhi_ptr->debug.rx_interrupts_count
		},
		{
			"tx_ring_full_count",
			&rmnet_mhi_ptr->debug.tx_ring_full_count
		},
		{
			"tx_queued_packets_count",
			&rmnet_mhi_ptr->debug.tx_queued_packets_count
		},
		{
			"rx_interrupts_in_masked_irq",
			&rmnet_mhi_ptr->
			debug.rx_interrupts_in_masked_irq
		},
		{
			"rx_napi_skb_burst_min",
			&rmnet_mhi_ptr->debug.rx_napi_skb_burst_min
		},
		{
			"rx_napi_skb_burst_max",
			&rmnet_mhi_ptr->debug.rx_napi_skb_burst_max
		},
		{
			"tx_cb_skb_free_burst_min",
			&rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_min
		},
		{
			"tx_cb_skb_free_burst_max",
			&rmnet_mhi_ptr->debug.tx_cb_skb_free_burst_max
		},
		{
			"rx_napi_budget_overflow",
			&rmnet_mhi_ptr->debug.rx_napi_budget_overflow
		},
		{
			"rx_fragmentation",
			&rmnet_mhi_ptr->debug.rx_fragmentation
		},
		{
			NULL, NULL
		},
	};

	/* Both tx & rx client handle contain same device info */
	client_handle = rmnet_mhi_ptr->rx_client_handle;
	if (!client_handle)
		client_handle = rmnet_mhi_ptr->tx_client_handle;

	snprintf(node_name,
		 sizeof(node_name),
		 "%s_%04x_%02u.%02u.%02u_%u",
		 rmnet_mhi_ptr->interface_name,
		 client_handle->dev_id,
		 client_handle->domain,
		 client_handle->bus,
		 client_handle->slot,
		 rmnet_mhi_ptr->dev_id);

	if (IS_ERR_OR_NULL(dentry))
		return;

	rmnet_mhi_ptr->dentry = debugfs_create_dir(node_name, dentry);
	if (IS_ERR_OR_NULL(rmnet_mhi_ptr->dentry))
		return;

	file = debugfs_create_u32("msg_lvl",
				  mode,
				  rmnet_mhi_ptr->dentry,
				  (u32 *)&rmnet_mhi_ptr->debug.rmnet_msg_lvl);
	if (IS_ERR_OR_NULL(file))
		return;

	file = debugfs_create_u32("ipc_log_lvl",
				  mode,
				  rmnet_mhi_ptr->dentry,
				  (u32 *)&rmnet_mhi_ptr->
				  debug.rmnet_ipc_log_lvl);
	if (IS_ERR_OR_NULL(file))
		return;

	file = debugfs_create_u32("mru",
				  mode,
				  rmnet_mhi_ptr->dentry,
				  &rmnet_mhi_ptr->mru);
	if (IS_ERR_OR_NULL(file))
		return;

	/* Add debug stats table */
	for (i = 0; debugfs_table[i].name; i++) {
		file = debugfs_create_u64(debugfs_table[i].name,
					  mode,
					  rmnet_mhi_ptr->dentry,
					  debugfs_table[i].ptr);
		if (IS_ERR_OR_NULL(file))
			return;
	}
}

static void rmnet_mhi_create_debugfs_dir(void)
{
	dentry = debugfs_create_dir(RMNET_MHI_DRIVER_NAME, 0);
}
#else
static void rmnet_mhi_create_debugfs(struct rmnet_mhi_private *rmnet_mhi_ptr)
{
}

static void rmnet_mhi_create_debugfs_dir(void)
{
}
#endif

static int rmnet_mhi_probe(struct platform_device *pdev)
{
	int rc;
	u32 channel;
	struct rmnet_mhi_private *rmnet_mhi_ptr;
	struct mhi_client_handle *client_handle = NULL;
	char node_name[32];
	struct mhi_client_info_t client_info;

	if (unlikely(!pdev->dev.of_node))
		return -ENODEV;

	if (!mhi_is_device_ready(&pdev->dev, "qcom,mhi"))
		return -EPROBE_DEFER;

	pdev->id = of_alias_get_id(pdev->dev.of_node, "mhi_rmnet");
	if (unlikely(pdev->id < 0))
		return -ENODEV;

	rmnet_mhi_ptr = kzalloc(sizeof(*rmnet_mhi_ptr), GFP_KERNEL);
	if (unlikely(!rmnet_mhi_ptr))
		return -ENOMEM;
	rmnet_mhi_ptr->pdev = pdev;
	spin_lock_init(&rmnet_mhi_ptr->out_chan_full_lock);
	rwlock_init(&rmnet_mhi_ptr->pm_lock);

	rc = of_property_read_u32(pdev->dev.of_node,
				  "qcom,mhi-mru",
				  &rmnet_mhi_ptr->mru);
	if (unlikely(rc)) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_CRITICAL,
			  "failed to get valid mru\n");
			goto probe_fail;
	}

	rc = of_property_read_u32(pdev->dev.of_node,
				  "cell-index",
				  &rmnet_mhi_ptr->dev_id);
	if (unlikely(rc)) {
		rmnet_log(rmnet_mhi_ptr,
			  MSG_CRITICAL,
			  "failed to get valid 'cell-index'\n");
		goto probe_fail;
	}

	rc = of_property_read_u32(pdev->dev.of_node,
				  "qcom,mhi-max-mru",
				  &rmnet_mhi_ptr->max_mru);
	if (likely(rc)) {
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "max-mru not defined, setting to max %d\n",
			  MHI_MAX_MRU);
		rmnet_mhi_ptr->max_mru = MHI_MAX_MRU;
	}

	rc = of_property_read_u32(pdev->dev.of_node,
				  "qcom,mhi-max-mtu",
				  &rmnet_mhi_ptr->max_mtu);
	if (likely(rc)) {
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "max-mtu not defined, setting to max %d\n",
			  MHI_MAX_MTU);
		rmnet_mhi_ptr->max_mtu = MHI_MAX_MTU;
	}

	rc = of_property_read_string(pdev->dev.of_node, "qcom,interface-name",
				     &rmnet_mhi_ptr->interface_name);
	if (likely(rc)) {
		rmnet_log(rmnet_mhi_ptr, MSG_INFO,
			  "interface-name not defined, setting to default name %s\n",
			  RMNET_MHI_DRIVER_NAME);
		rmnet_mhi_ptr->interface_name = rmnet_mhi_driver.driver.name;
	}

	client_info.dev = &pdev->dev;
	client_info.node_name = "qcom,mhi";
	client_info.mhi_client_cb = rmnet_mhi_cb;
	client_info.user_data = rmnet_mhi_ptr;

	rc = of_property_read_u32(pdev->dev.of_node,
				  "qcom,mhi-tx-channel",
				  &channel);
	if (rc == 0) {
		rmnet_mhi_ptr->tx_channel = channel;
		client_info.chan = channel;
		client_info.max_payload = rmnet_mhi_ptr->max_mtu;

		rc = mhi_register_channel(&rmnet_mhi_ptr->tx_client_handle,
					  &client_info);
		if (unlikely(rc)) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "mhi_register_channel failed chan %d ret %d\n",
				  rmnet_mhi_ptr->tx_channel,
				  rc);
			goto probe_fail;
		}
		client_handle = rmnet_mhi_ptr->tx_client_handle;
	}

	rc = of_property_read_u32(pdev->dev.of_node,
				  "qcom,mhi-rx-channel",
				  &channel);
	if (rc == 0) {
		rmnet_mhi_ptr->rx_channel = channel;
		client_info.max_payload = rmnet_mhi_ptr->max_mru;
		client_info.chan = channel;
		rc = mhi_register_channel(&rmnet_mhi_ptr->rx_client_handle,
					  &client_info);
		if (unlikely(rc)) {
			rmnet_log(rmnet_mhi_ptr,
				  MSG_CRITICAL,
				  "mhi_register_channel failed chan %d ret %d\n",
				  rmnet_mhi_ptr->rx_channel,
				  rc);
			goto probe_fail;
		}
		/* overwriting tx_client_handle is ok because dev_id and
		 * bdf are same for both channels
		 */
		client_handle = rmnet_mhi_ptr->rx_client_handle;
		INIT_WORK(&rmnet_mhi_ptr->alloc_work, rmnet_mhi_alloc_work);
		spin_lock_init(&rmnet_mhi_ptr->alloc_lock);
	}

	/* We must've have @ least one valid channel */
	if (!client_handle) {
		rmnet_log(rmnet_mhi_ptr, MSG_CRITICAL,
			  "No registered channels\n");
		rc = -ENODEV;
		goto probe_fail;
	}

	snprintf(node_name,
		 sizeof(node_name),
		 "%s_%04x_%02u.%02u.%02u_%u",
		 rmnet_mhi_ptr->interface_name,
		 client_handle->dev_id,
		 client_handle->domain,
		 client_handle->bus,
		 client_handle->slot,
		 rmnet_mhi_ptr->dev_id);
#ifdef CONFIG_IPC_LOGGING
	rmnet_mhi_ptr->rmnet_ipc_log =
		ipc_log_context_create(RMNET_IPC_LOG_PAGES,
				       node_name, 0);
#endif
	rmnet_mhi_ptr->debug.rmnet_msg_lvl = MSG_CRITICAL;

#ifdef CONFIG_MSM_MHI_DEBUG
	rmnet_mhi_ptr->debug.rmnet_ipc_log_lvl = MSG_VERBOSE;
#else
	rmnet_mhi_ptr->debug.rmnet_ipc_log_lvl = MSG_ERROR;
#endif

	rmnet_mhi_create_debugfs(rmnet_mhi_ptr);
	list_add_tail(&rmnet_mhi_ptr->node, &rmnet_mhi_ctxt_list);
	return 0;

probe_fail:
	kfree(rmnet_mhi_ptr);
	return rc;
}

static const struct of_device_id msm_mhi_match_table[] = {
	{.compatible = "qcom,mhi-rmnet"},
	{},
};

static struct platform_driver rmnet_mhi_driver = {
	.probe = rmnet_mhi_probe,
	.driver = {
		.name = RMNET_MHI_DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = msm_mhi_match_table,
	},
};

static int __init rmnet_mhi_init(void)
{
	rmnet_mhi_create_debugfs_dir();

	return platform_driver_register(&rmnet_mhi_driver);
}

static void __exit rmnet_mhi_exit(void)
{
	struct rmnet_mhi_private *rmnet_mhi_ptr = 0;

	list_for_each_entry(rmnet_mhi_ptr, &rmnet_mhi_ctxt_list, node) {
		if (rmnet_mhi_ptr->tx_client_handle)
			mhi_deregister_channel(rmnet_mhi_ptr->tx_client_handle);
		if (rmnet_mhi_ptr->rx_client_handle)
			mhi_deregister_channel(rmnet_mhi_ptr->rx_client_handle);
	}
}

module_exit(rmnet_mhi_exit);
module_init(rmnet_mhi_init);

MODULE_DESCRIPTION("MHI RMNET Network Interface");
MODULE_LICENSE("GPL v2");
