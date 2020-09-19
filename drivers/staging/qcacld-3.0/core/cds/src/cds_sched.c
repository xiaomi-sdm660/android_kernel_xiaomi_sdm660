/*
 * Copyright (c) 2014-2020 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 *  File: cds_sched.c
 *
 *  DOC: CDS Scheduler Implementation
 */

 /* Include Files */
#include <cds_mq.h>
#include <cds_api.h>
#include <ani_global.h>
#include <sir_types.h>
#include <qdf_threads.h>
#include <qdf_types.h>
#include <lim_api.h>
#include <sme_api.h>
#include <wlan_qct_sys.h>
#include "cds_sched.h"
#include <wlan_hdd_power.h>
#include "wma_types.h"
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/cpu.h>
/* Preprocessor Definitions and Constants */
#define CDS_SCHED_THREAD_HEART_BEAT    INFINITE
/* Milli seconds to delay SSR thread when an Entry point is Active */
#define SSR_WAIT_SLEEP_TIME 200
/* MAX iteration count to wait for Entry point to exit before
 * we proceed with SSR in WD Thread
 */
#define MAX_SSR_WAIT_ITERATIONS 100
#define MAX_SSR_PROTECT_LOG (16)

static atomic_t ssr_protect_entry_count;

/**
 * struct ssr_protect - sub system restart(ssr) protection tracking table
 * @func: Function which needs ssr protection
 * @free: Flag to tell whether entry is free in table or not
 * @pid: Process id which needs ssr protection
 */
struct ssr_protect {
	const char *func;
	bool  free;
	uint32_t pid;
};

static spinlock_t ssr_protect_lock;
static struct ssr_protect ssr_protect_log[MAX_SSR_PROTECT_LOG];

struct shutdown_notifier {
	struct list_head list;
	void (*cb)(void *priv);
	void *priv;
};

struct list_head shutdown_notifier_head;

enum notifier_state {
	NOTIFIER_STATE_NONE,
	NOTIFIER_STATE_NOTIFYING,
} notifier_state;

struct _cds_sched_context *gp_cds_sched_context;
static int cds_mc_thread(void *Arg);
static int cds_ol_mon_thread(void *arg);
static QDF_STATUS cds_alloc_ol_mon_pkt_freeq(p_cds_sched_context pSchedContext);

static inline
int cds_set_cpus_allowed_ptr(struct task_struct *task, unsigned long cpu)
{
	return set_cpus_allowed_ptr(task, cpumask_of(cpu));
}

#ifdef QCA_CONFIG_SMP
static int cds_ol_rx_thread(void *arg);
static uint32_t affine_cpu;
static QDF_STATUS cds_alloc_ol_rx_pkt_freeq(p_cds_sched_context pSchedContext);

#define CDS_CORE_PER_CLUSTER (4)
/*Maximum 2 clusters supported*/
#define CDS_MAX_CPU_CLUSTERS 2

#define CDS_CPU_CLUSTER_TYPE_LITTLE 0
#define CDS_CPU_CLUSTER_TYPE_PERF 1

/**
 * cds_sched_find_attach_cpu - find available cores and attach to required core
 * @pSchedContext:	wlan scheduler context
 * @high_throughput:	high throughput is required or not
 *
 * Find current online cores.
 * high troughput required and PERF core online, then attach to last PERF core
 * low throughput required or only little cores online, the attach any little
 * core
 *
 * Return: 0 success
 *         1 fail
 */
static int cds_sched_find_attach_cpu(p_cds_sched_context pSchedContext,
	bool high_throughput)
{
	unsigned long *online_perf_cpu = NULL;
	unsigned long *online_litl_cpu = NULL;
	unsigned char perf_core_count = 0;
	unsigned char litl_core_count = 0;
	int cds_max_cluster_id = 0;
#ifdef WLAN_OPEN_SOURCE
	struct cpumask litl_mask;
	unsigned long cpus;
	int i;
#endif

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
		"%s: num possible cpu %d",
		__func__, num_possible_cpus());

	online_perf_cpu = qdf_mem_malloc(
		num_possible_cpus() * sizeof(unsigned long));
	if (!online_perf_cpu) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: perf cpu cache alloc fail", __func__);
		return 1;
	}

	online_litl_cpu = qdf_mem_malloc(
		num_possible_cpus() * sizeof(unsigned long));
	if (!online_litl_cpu) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: lttl cpu cache alloc fail", __func__);
		qdf_mem_free(online_perf_cpu);
		return 1;
	}

	/* Get Online perf CPU count */
#if defined(WLAN_OPEN_SOURCE) && \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
	for_each_online_cpu(cpus) {
		if (topology_physical_package_id(cpus) > CDS_MAX_CPU_CLUSTERS) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				"%s: can handle max %d clusters, returning...",
				__func__, CDS_MAX_CPU_CLUSTERS);
			goto err;
		}

		if (topology_physical_package_id(cpus) ==
					 CDS_CPU_CLUSTER_TYPE_PERF) {
			online_perf_cpu[perf_core_count] = cpus;
			perf_core_count++;
		} else {
			online_litl_cpu[litl_core_count] = cpus;
			litl_core_count++;
		}
		cds_max_cluster_id =  topology_physical_package_id(cpus);
	}
#else
	cds_max_cluster_id = 0;
#endif

	/* Single cluster system, not need to handle this */
	if (0 == cds_max_cluster_id) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_LOW,
		"%s: single cluster system. returning", __func__);
		goto success;
	}

	if ((!litl_core_count) && (!perf_core_count)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: Both Cluster off, do nothing", __func__);
		goto success;
	}

	if ((high_throughput && perf_core_count) || (!litl_core_count)) {
		/* Attach RX thread to PERF CPU */
		if (pSchedContext->rx_thread_cpu !=
			online_perf_cpu[perf_core_count - 1]) {
			if (cds_set_cpus_allowed_ptr(
				pSchedContext->ol_rx_thread,
				online_perf_cpu[perf_core_count - 1])) {
				QDF_TRACE(QDF_MODULE_ID_QDF,
					QDF_TRACE_LEVEL_ERROR,
					"%s: rx thread perf core set fail",
					__func__);
				goto err;
			}
			pSchedContext->rx_thread_cpu =
				online_perf_cpu[perf_core_count - 1];
		}
	} else {
#if defined(WLAN_OPEN_SOURCE) && \
	 (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
		/* Attach to any little core
		 * Final decision should made by scheduler */

		cpumask_clear(&litl_mask);
		for (i = 0; i < litl_core_count; i++)
			cpumask_set_cpu(online_litl_cpu[i], &litl_mask);

		set_cpus_allowed_ptr(pSchedContext->ol_rx_thread, &litl_mask);
		pSchedContext->rx_thread_cpu = 0;
#else

		/* Attach RX thread to last little core CPU */
		if (pSchedContext->rx_thread_cpu !=
			online_perf_cpu[litl_core_count - 1]) {
			if (cds_set_cpus_allowed_ptr(
				pSchedContext->ol_rx_thread,
				online_perf_cpu[litl_core_count - 1])) {
				QDF_TRACE(QDF_MODULE_ID_QDF,
					QDF_TRACE_LEVEL_ERROR,
					"%s: rx thread litl core set fail",
					__func__);
				goto err;
			}
			pSchedContext->rx_thread_cpu =
				online_perf_cpu[litl_core_count - 1];
		}
#endif /* WLAN_OPEN_SOURCE */
	}

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
		"%s: NUM PERF CORE %d, HIGH TPUTR REQ %d, RX THRE CPU %lu",
		__func__, perf_core_count,
		(int)pSchedContext->high_throughput_required,
		pSchedContext->rx_thread_cpu);

success:
	qdf_mem_free(online_perf_cpu);
	qdf_mem_free(online_litl_cpu);
	return 0;

err:
	qdf_mem_free(online_perf_cpu);
	qdf_mem_free(online_litl_cpu);
	return 1;
}

/**
 * cds_sched_handle_cpu_hot_plug - cpu hotplug event handler
 *
 * cpu hotplug indication handler
 * will find online cores and will assign proper core based on perf requirement
 *
 * Return: 0 success
 *         1 fail
 */
int cds_sched_handle_cpu_hot_plug(void)
{
	p_cds_sched_context pSchedContext = get_cds_sched_ctxt();

	if (!pSchedContext) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: invalid context", __func__);
		return 1;
	}

	if (cds_is_load_or_unload_in_progress())
		return 0;

	mutex_lock(&pSchedContext->affinity_lock);
	if (cds_sched_find_attach_cpu(pSchedContext,
		pSchedContext->high_throughput_required)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: handle hot plug fail", __func__);
		mutex_unlock(&pSchedContext->affinity_lock);
		return 1;
	}
	mutex_unlock(&pSchedContext->affinity_lock);
	return 0;
}

/**
 * cds_sched_handle_throughput_req - cpu throughput requirement handler
 * @high_tput_required:	high throughput is required or not
 *
 * high or low throughput indication ahndler
 * will find online cores and will assign proper core based on perf requirement
 *
 * Return: 0 success
 *         1 fail
 */
int cds_sched_handle_throughput_req(bool high_tput_required)
{
	p_cds_sched_context pSchedContext = get_cds_sched_ctxt();

	if (!pSchedContext) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: invalid context", __func__);
		return 1;
	}

	if (cds_is_load_or_unload_in_progress()) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: load or unload in progress", __func__);
		return 0;
	}

	mutex_lock(&pSchedContext->affinity_lock);
	pSchedContext->high_throughput_required = high_tput_required;
	if (cds_sched_find_attach_cpu(pSchedContext, high_tput_required)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			"%s: handle throughput req fail", __func__);
		mutex_unlock(&pSchedContext->affinity_lock);
		return 1;
	}
	mutex_unlock(&pSchedContext->affinity_lock);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
/**
 * cds_cpu_hotplug_multi_cluster() - calls the multi-cluster hotplug handler,
 *	when on a multi-cluster platform
 *
 * Return: QDF_STATUS
 */
static QDF_STATUS cds_cpu_hotplug_multi_cluster(void)
{
	int cpus;
	unsigned int multi_cluster = 0;

	for_each_online_cpu(cpus) {
		multi_cluster = topology_physical_package_id(cpus);
	}

	if (!multi_cluster)
		return QDF_STATUS_E_NOSUPPORT;

	if (cds_is_load_or_unload_in_progress() ||
	    cds_is_module_stop_in_progress() || cds_is_driver_recovering())
		return NOTIFY_OK;

	if (cds_sched_handle_cpu_hot_plug())
		return QDF_STATUS_E_FAILURE;

	return QDF_STATUS_SUCCESS;
}
#else
static QDF_STATUS cds_cpu_hotplug_multi_cluster(void)
{
	return QDF_STATUS_E_NOSUPPORT;
}
#endif /* KERNEL_VERSION(3, 10, 0) */

/**
 * __cds_cpu_hotplug_notify() - CPU hotplug event handler
 * @cpu: CPU Id of the CPU generating the event
 * @cpu_up: true if the CPU is online
 *
 * Return: None
 */
static void __cds_cpu_hotplug_notify(uint32_t cpu, bool cpu_up)
{
	unsigned long pref_cpu = 0;
	p_cds_sched_context pSchedContext = get_cds_sched_ctxt();
	int i;

	if (!pSchedContext || !pSchedContext->ol_rx_thread)
		return;

	if (cds_is_load_or_unload_in_progress())
		return;

	cds_debug("'%s' event on CPU %u (of %d); Currently affine to CPU %u",
		  cpu_up ? "Up" : "Down", cpu, num_possible_cpus(), affine_cpu);

	/* try multi-cluster scheduling first */
	if (QDF_IS_STATUS_SUCCESS(cds_cpu_hotplug_multi_cluster()))
		return;

	if (cpu_up) {
		if (affine_cpu != 0)
			return;

		for_each_online_cpu(i) {
			if (i == 0)
				continue;
			pref_cpu = i;
			break;
		}
	} else {
		if (cpu != affine_cpu)
			return;

		affine_cpu = 0;
		for_each_online_cpu(i) {
			if (i == 0)
				continue;
			pref_cpu = i;
			break;
		}
	}

	if (pref_cpu == 0)
		return;

	if (pSchedContext->ol_rx_thread &&
	    !cds_set_cpus_allowed_ptr(pSchedContext->ol_rx_thread, pref_cpu))
		affine_cpu = pref_cpu;
}

/**
 * cds_cpu_hotplug_notify - cpu core up/down notification handler wrapper
 * @cpu: CPU Id of the CPU generating the event
 * @cpu_up: true if the CPU is online
 *
 * Return: None
 */
static void cds_cpu_hotplug_notify(uint32_t cpu, bool cpu_up)
{
	cds_ssr_protect(__func__);
	__cds_cpu_hotplug_notify(cpu, cpu_up);
	cds_ssr_unprotect(__func__);
}

static void cds_cpu_online_cb(void *context, uint32_t cpu)
{
	cds_cpu_hotplug_notify(cpu, true);
}

static void cds_cpu_before_offline_cb(void *context, uint32_t cpu)
{
	cds_cpu_hotplug_notify(cpu, false);
}
#endif /* QCA_CONFIG_SMP */

/**
 * cds_sched_open() - initialize the CDS Scheduler
 * @p_cds_context: Pointer to the global CDS Context
 * @pSchedContext: Pointer to a previously allocated buffer big
 *	enough to hold a scheduler context.
 * @SchedCtxSize: CDS scheduler context size
 *
 * This function initializes the CDS Scheduler
 * Upon successful initialization:
 *	- All the message queues are initialized
 *	- The Main Controller thread is created and ready to receive and
 *	dispatch messages.
 *
 *
 * Return: QDF status
 */
QDF_STATUS cds_sched_open(void *p_cds_context,
		p_cds_sched_context pSchedContext,
		uint32_t SchedCtxSize)
{
	QDF_STATUS vStatus = QDF_STATUS_SUCCESS;

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Opening the CDS Scheduler", __func__);
	/* Sanity checks */
	if ((p_cds_context == NULL) || (pSchedContext == NULL)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Null params being passed", __func__);
		return QDF_STATUS_E_FAILURE;
	}
	if (sizeof(cds_sched_context) != SchedCtxSize) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: Incorrect CDS Sched Context size passed",
			  __func__);
		return QDF_STATUS_E_INVAL;
	}
	qdf_mem_zero(pSchedContext, sizeof(cds_sched_context));
	pSchedContext->pVContext = p_cds_context;
	vStatus = cds_sched_init_mqs(pSchedContext);
	if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Failed to initialize CDS Scheduler MQs",
			  __func__);
		return vStatus;
	}
	/* Initialize the helper events and event queues */
	init_completion(&pSchedContext->McStartEvent);
	init_completion(&pSchedContext->McShutdown);
	init_completion(&pSchedContext->ResumeMcEvent);

	spin_lock_init(&pSchedContext->McThreadLock);
#ifdef QCA_CONFIG_SMP
	spin_lock_init(&pSchedContext->ol_rx_thread_lock);
#endif

	init_waitqueue_head(&pSchedContext->mcWaitQueue);
	pSchedContext->mcEventFlag = 0;

#ifdef QCA_CONFIG_SMP
	init_waitqueue_head(&pSchedContext->ol_rx_wait_queue);
	init_completion(&pSchedContext->ol_rx_start_event);
	init_completion(&pSchedContext->ol_suspend_rx_event);
	init_completion(&pSchedContext->ol_resume_rx_event);
	init_completion(&pSchedContext->ol_rx_shutdown);
	pSchedContext->ol_rx_event_flag = 0;
	spin_lock_init(&pSchedContext->ol_rx_queue_lock);
	spin_lock_init(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	INIT_LIST_HEAD(&pSchedContext->ol_rx_thread_queue);
	spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	INIT_LIST_HEAD(&pSchedContext->cds_ol_rx_pkt_freeq);
	spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	if (cds_alloc_ol_rx_pkt_freeq(pSchedContext) != QDF_STATUS_SUCCESS)
		goto pkt_freeqalloc_failure;
	qdf_cpuhp_register(&pSchedContext->cpuhp_event_handle,
			   NULL,
			   cds_cpu_online_cb,
			   cds_cpu_before_offline_cb);
	mutex_init(&pSchedContext->affinity_lock);
	pSchedContext->high_throughput_required = false;
#endif
	if (cds_get_pktcap_mode_enable()) {
		spin_lock_init(&pSchedContext->ol_mon_thread_lock);
		init_waitqueue_head(&pSchedContext->ol_mon_wait_queue);
		init_completion(&pSchedContext->ol_mon_start_event);
		init_completion(&pSchedContext->ol_suspend_mon_event);
		init_completion(&pSchedContext->ol_resume_mon_event);
		init_completion(&pSchedContext->ol_mon_shutdown);
		pSchedContext->ol_mon_event_flag = 0;
		spin_lock_init(&pSchedContext->ol_mon_queue_lock);
		spin_lock_init(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		INIT_LIST_HEAD(&pSchedContext->ol_mon_thread_queue);
		spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		INIT_LIST_HEAD(&pSchedContext->cds_ol_mon_pkt_freeq);
		spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		if (cds_alloc_ol_mon_pkt_freeq(pSchedContext) !=
		    QDF_STATUS_SUCCESS)
			goto mon_freeqalloc_failure;
	}

	gp_cds_sched_context = pSchedContext;

	/* Create the CDS Main Controller thread */
	pSchedContext->McThread = kthread_create(cds_mc_thread, pSchedContext,
						 "cds_mc_thread");
	if (IS_ERR(pSchedContext->McThread)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_FATAL,
			  "%s: Could not Create CDS Main Thread Controller",
			  __func__);
		goto MC_THREAD_START_FAILURE;
	}
	wake_up_process(pSchedContext->McThread);
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: CDS Main Controller thread Created", __func__);

#ifdef QCA_CONFIG_SMP
	pSchedContext->ol_rx_thread = kthread_create(cds_ol_rx_thread,
						       pSchedContext,
						       "cds_ol_rx_thread");
	if (IS_ERR(pSchedContext->ol_rx_thread)) {

		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_FATAL,
			  "%s: Could not Create CDS OL RX Thread",
			  __func__);
		goto OL_RX_THREAD_START_FAILURE;

	}
	wake_up_process(pSchedContext->ol_rx_thread);
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  ("CDS OL RX thread Created"));
#endif
	if (cds_get_pktcap_mode_enable()) {
		pSchedContext->ol_mon_thread = kthread_create(cds_ol_mon_thread,
							       pSchedContext,
							       "cds_ol_mon_thread");
		if (IS_ERR(pSchedContext->ol_mon_thread)) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_FATAL,
				  "%s: Could not Create CDS OL MON Thread",
				  __func__);
			goto OL_MON_THREAD_START_FAILURE;
		}
		wake_up_process(pSchedContext->ol_mon_thread);
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
			  ("CDS OL MON thread Created"));
	}
	/*
	 * Now make sure all threads have started before we exit.
	 * Each thread should normally ACK back when it starts.
	 */
	wait_for_completion_interruptible(&pSchedContext->McStartEvent);
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: CDS MC Thread has started", __func__);
#ifdef QCA_CONFIG_SMP
	wait_for_completion_interruptible(&pSchedContext->ol_rx_start_event);
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: CDS OL Rx Thread has started", __func__);
#endif
	if (cds_get_pktcap_mode_enable()) {
		wait_for_completion_interruptible(
					&pSchedContext->ol_mon_start_event);
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
			  "%s: CDS OL MON Thread has started", __func__);
	}

	/* We're good now: Let's get the ball rolling!!! */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: CDS Scheduler successfully Opened", __func__);
	return QDF_STATUS_SUCCESS;

OL_MON_THREAD_START_FAILURE:
#ifdef QCA_CONFIG_SMP
	/* Try and force the Main thread controller to exit */
	set_bit(RX_SHUTDOWN_EVENT, &pSchedContext->ol_rx_event_flag);
	set_bit(RX_POST_EVENT, &pSchedContext->ol_rx_event_flag);
	wake_up_interruptible(&pSchedContext->ol_rx_wait_queue);
	/* Wait for RX Thread to exit */
	wait_for_completion(&pSchedContext->ol_rx_shutdown);
OL_RX_THREAD_START_FAILURE:
#endif
	/* Try and force the Main thread controller to exit */
	set_bit(MC_SHUTDOWN_EVENT, &pSchedContext->mcEventFlag);
	set_bit(MC_POST_EVENT, &pSchedContext->mcEventFlag);
	wake_up_interruptible(&pSchedContext->mcWaitQueue);
	/* Wait for MC to exit */
	wait_for_completion_interruptible(&pSchedContext->McShutdown);

MC_THREAD_START_FAILURE:
	if (cds_get_pktcap_mode_enable())
		cds_free_ol_mon_pkt_freeq(gp_cds_sched_context);

mon_freeqalloc_failure:
#ifdef QCA_CONFIG_SMP
	qdf_cpuhp_unregister(&pSchedContext->cpuhp_event_handle);
	cds_free_ol_rx_pkt_freeq(gp_cds_sched_context);
pkt_freeqalloc_failure:
#endif
	/* De-initialize all the message queues */
	cds_sched_deinit_mqs(pSchedContext);
	gp_cds_sched_context = NULL;

	return QDF_STATUS_E_RESOURCES;

} /* cds_sched_open() */

#define MC_THRD_WD_TIMEOUT (60 * 1000) /* 60s */

static void cds_mc_thread_watchdog_notify(cds_msg_t *msg)
{
	char symbol[QDF_SYMBOL_LEN];

	if (!msg) {
		cds_err("msg is null");
		return;
	}

	if (msg->callback)
		qdf_sprint_symbol(symbol, msg->callback);

	cds_err("WLAN_BUG_RCA: Callback %s (type 0x%x) exceeded its allotted time of %ds",
		msg->callback ? symbol : "<null>", msg->type,
		MC_THRD_WD_TIMEOUT / 1000);
}

#ifdef CONFIG_SLUB_DEBUG_ON
static void cds_mc_thread_watchdog_timeout(unsigned long arg)
{
	cds_msg_t *msg = *(cds_msg_t **)arg;

	cds_mc_thread_watchdog_notify(msg);

	if (gp_cds_sched_context) {
		qdf_thread_t *mc_thread =
			(qdf_thread_t *)gp_cds_sched_context->McThread;
		if (mc_thread)
			qdf_print_thread_trace(mc_thread);
	}

	if (cds_is_driver_recovering())
		return;

	cds_alert("Going down for MC Thread Watchdog Bite!");
	QDF_BUG(0);
}
#else
static inline void cds_mc_thread_watchdog_timeout(unsigned long arg)
{
	cds_msg_t *msg = *(cds_msg_t **)arg;

	cds_mc_thread_watchdog_notify(msg);
}
#endif

/**
 * cds_mc_thread() - cds main controller thread execution handler
 * @Arg: Pointer to the global CDS Sched Context
 *
 * Return: thread exit code
 */
static int cds_mc_thread(void *Arg)
{
	p_cds_sched_context pSchedContext = (p_cds_sched_context) Arg;
	p_cds_msg_wrapper pMsgWrapper = NULL;
	tpAniSirGlobal pMacContext = NULL;
	tSirRetStatus macStatus = eSIR_SUCCESS;
	QDF_STATUS vStatus = QDF_STATUS_SUCCESS;
	int retWaitStatus = 0;
	bool shutdown = false;
	hdd_context_t *pHddCtx = NULL;
	v_CONTEXT_t p_cds_context = NULL;
	qdf_timer_t wd_timer;
	cds_msg_t *wd_msg;

	if (Arg == NULL) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Bad Args passed", __func__);
		return 0;
	}
	set_user_nice(current, -2);

	/* Ack back to the context from which the main controller thread
	 * has been created
	 */
	complete(&pSchedContext->McStartEvent);
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: MC Thread %d (%s) starting up", __func__, current->pid,
		  current->comm);

	/* Get the Global CDS Context */
	p_cds_context = cds_get_global_context();
	if (!p_cds_context) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_FATAL,
			  "%s: Global CDS context is Null", __func__);
		return 0;
	}

	pHddCtx = cds_get_context(QDF_MODULE_ID_HDD);
	if (!pHddCtx) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_FATAL,
			  "%s: HDD context is Null", __func__);
		return 0;
	}

	/* initialize MC thread watchdog timer */
	qdf_timer_init(NULL, &wd_timer, &cds_mc_thread_watchdog_timeout,
		       &wd_msg, QDF_TIMER_TYPE_SW);

	while (!shutdown) {
		/* This implements the execution model algorithm */
		retWaitStatus =
			wait_event_interruptible(pSchedContext->mcWaitQueue,
						 test_bit(MC_POST_EVENT,
							  &pSchedContext->mcEventFlag)
						 || test_bit(MC_SUSPEND_EVENT,
							     &pSchedContext->mcEventFlag));

		if (retWaitStatus == -ERESTARTSYS) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				  "%s: wait_event_interruptible returned -ERESTARTSYS",
				  __func__);
			QDF_BUG(0);
		}
		clear_bit(MC_POST_EVENT, &pSchedContext->mcEventFlag);

		while (1) {
			/* Check if MC needs to shutdown */
			if (test_bit
				    (MC_SHUTDOWN_EVENT,
				    &pSchedContext->mcEventFlag)) {
				QDF_TRACE(QDF_MODULE_ID_QDF,
					  QDF_TRACE_LEVEL_INFO,
					  "%s: MC thread signaled to shutdown",
					  __func__);
				shutdown = true;
				/* Check for any Suspend Indication */
				if (test_bit
					    (MC_SUSPEND_EVENT,
					    &pSchedContext->mcEventFlag)) {
					clear_bit(MC_SUSPEND_EVENT,
						  &pSchedContext->mcEventFlag);

					/* Unblock anyone waiting on suspend */
					complete(&pHddCtx->mc_sus_event_var);
				}
				break;
			}
			/* Check the SYS queue first */
			if (!cds_is_mq_empty(&pSchedContext->sysMcMq)) {
				/* Service the SYS message queue */
				pMsgWrapper =
					cds_mq_get(&pSchedContext->sysMcMq);
				if (pMsgWrapper == NULL) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: pMsgWrapper is NULL",
						  __func__);
					QDF_ASSERT(0);
					break;
				}

				qdf_timer_start(&wd_timer, MC_THRD_WD_TIMEOUT);
				wd_msg = pMsgWrapper->pVosMsg;
				vStatus =
					sys_mc_process_msg(pSchedContext->pVContext,
							   pMsgWrapper->pVosMsg);
				qdf_timer_stop(&wd_timer);

				if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: Issue Processing SYS message",
						  __func__);
				}
				/* return message to the Core */
				cds_core_return_msg(pSchedContext->pVContext,
						    pMsgWrapper);
				continue;
			}
			/* Check the WMA queue */
			if (!cds_is_mq_empty(&pSchedContext->wmaMcMq)) {
				/* Service the WMA message queue */
				pMsgWrapper =
					cds_mq_get(&pSchedContext->wmaMcMq);
				if (pMsgWrapper == NULL) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: pMsgWrapper is NULL",
						  __func__);
					QDF_ASSERT(0);
					break;
				}

				qdf_timer_start(&wd_timer, MC_THRD_WD_TIMEOUT);
				wd_msg = pMsgWrapper->pVosMsg;
				vStatus =
					wma_mc_process_msg(pSchedContext->pVContext,
							 pMsgWrapper->pVosMsg);
				qdf_timer_stop(&wd_timer);

				if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: Issue Processing WMA message",
						  __func__);
				}
				/* return message to the Core */
				cds_core_return_msg(pSchedContext->pVContext,
						    pMsgWrapper);
				continue;
			}
			/* Check the PE queue */
			if (!cds_is_mq_empty(&pSchedContext->peMcMq)) {
				/* Service the PE message queue */
				pMsgWrapper =
					cds_mq_get(&pSchedContext->peMcMq);
				if (NULL == pMsgWrapper) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: pMsgWrapper is NULL",
						  __func__);
					QDF_ASSERT(0);
					break;
				}
				/* Need some optimization */
				pMacContext =
					cds_get_context(QDF_MODULE_ID_PE);
				if (NULL == pMacContext) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_INFO,
						  "MAC Context not ready yet");
					cds_core_return_msg
						(pSchedContext->pVContext,
						pMsgWrapper);
					continue;
				}

				qdf_timer_start(&wd_timer, MC_THRD_WD_TIMEOUT);
				wd_msg = pMsgWrapper->pVosMsg;
				macStatus =
					pe_process_messages(pMacContext,
							    (tSirMsgQ *)
							    pMsgWrapper->pVosMsg);
				qdf_timer_stop(&wd_timer);

				if (eSIR_SUCCESS != macStatus) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: Issue Processing PE message",
						  __func__);
				}
				/* return message to the Core */
				cds_core_return_msg(pSchedContext->pVContext,
						    pMsgWrapper);
				continue;
			}
			/** Check the SME queue **/
			if (!cds_is_mq_empty(&pSchedContext->smeMcMq)) {
				/* Service the SME message queue */
				pMsgWrapper =
					cds_mq_get(&pSchedContext->smeMcMq);
				if (NULL == pMsgWrapper) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_ERROR,
						  "%s: pMsgWrapper is NULL",
						  __func__);
					QDF_ASSERT(0);
					break;
				}
				/* Need some optimization */
				pMacContext =
					cds_get_context(QDF_MODULE_ID_SME);
				if (NULL == pMacContext) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_INFO,
						  "MAC Context not ready yet");
					cds_core_return_msg
						(pSchedContext->pVContext,
						pMsgWrapper);
					continue;
				}

				qdf_timer_start(&wd_timer, MC_THRD_WD_TIMEOUT);
				wd_msg = pMsgWrapper->pVosMsg;
				vStatus =
					sme_process_msg((tHalHandle)pMacContext,
							pMsgWrapper->pVosMsg);
				qdf_timer_stop(&wd_timer);

				if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
					QDF_TRACE(QDF_MODULE_ID_QDF,
						  QDF_TRACE_LEVEL_INFO,
						  "%s: Issue Processing SME message",
						  __func__);
				}
				/* return message to the Core */
				cds_core_return_msg(pSchedContext->pVContext,
						    pMsgWrapper);
				continue;
			}
			/* Check for any Suspend Indication */
			if (test_bit
				    (MC_SUSPEND_EVENT,
				    &pSchedContext->mcEventFlag)) {
				clear_bit(MC_SUSPEND_EVENT,
					  &pSchedContext->mcEventFlag);
				spin_lock(&pSchedContext->McThreadLock);
				INIT_COMPLETION(pSchedContext->ResumeMcEvent);
				/* Mc Thread Suspended */
				complete(&pHddCtx->mc_sus_event_var);

				spin_unlock(&pSchedContext->McThreadLock);

				/* Wait foe Resume Indication */
				wait_for_completion_interruptible
					(&pSchedContext->ResumeMcEvent);
			}
			break;  /* All queues are empty now */
		} /* while message loop processing */
	} /* while true */

	/* If we get here the MC thread must exit */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "%s: MC Thread exiting!!!!", __func__);

	qdf_timer_free(&wd_timer);

	complete_and_exit(&pSchedContext->McShutdown, 0);

	return 0;
} /* cds_mc_thread() */

#ifdef QCA_CONFIG_SMP
/**
 * cds_free_ol_rx_pkt_freeq() - free cds buffer free queue
 * @pSchedContext - pointer to the global CDS Sched Context
 *
 * This API does mem free of the buffers available in free cds buffer
 * queue which is used for Data rx processing.
 *
 * Return: none
 */
void cds_free_ol_rx_pkt_freeq(p_cds_sched_context pSchedContext)
{
	struct cds_ol_rx_pkt *pkt;

	spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	while (!list_empty(&pSchedContext->cds_ol_rx_pkt_freeq)) {
		pkt = list_entry((&pSchedContext->cds_ol_rx_pkt_freeq)->next,
			typeof(*pkt), list);
		list_del(&pkt->list);
		spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
		qdf_mem_free(pkt);
		spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	}
	spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
}

/**
 * cds_alloc_ol_rx_pkt_freeq() - Function to allocate free buffer queue
 * @pSchedContext - pointer to the global CDS Sched Context
 *
 * This API allocates CDS_MAX_OL_RX_PKT number of cds message buffers
 * which are used for Rx data processing.
 *
 * Return: status of memory allocation
 */
static QDF_STATUS cds_alloc_ol_rx_pkt_freeq(p_cds_sched_context pSchedContext)
{
	struct cds_ol_rx_pkt *pkt, *tmp;
	int i;

	for (i = 0; i < CDS_MAX_OL_RX_PKT; i++) {
		pkt = qdf_mem_malloc(sizeof(*pkt));
		if (!pkt) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				  "%s Vos packet allocation for ol rx thread failed",
				  __func__);
			goto free;
		}
		spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
		list_add_tail(&pkt->list, &pSchedContext->cds_ol_rx_pkt_freeq);
		spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	}

	return QDF_STATUS_SUCCESS;

free:
	spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	list_for_each_entry_safe(pkt, tmp, &pSchedContext->cds_ol_rx_pkt_freeq,
				 list) {
		list_del(&pkt->list);
		spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
		qdf_mem_free(pkt);
		spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	}
	spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	return QDF_STATUS_E_NOMEM;
}

/**
 * cds_free_ol_rx_pkt() - api to release cds message to the freeq
 * This api returns the cds message used for Rx data to the free queue
 * @pSchedContext: Pointer to the global CDS Sched Context
 * @pkt: CDS message buffer to be returned to free queue.
 *
 * Return: none
 */
void
cds_free_ol_rx_pkt(p_cds_sched_context pSchedContext,
		    struct cds_ol_rx_pkt *pkt)
{
	memset(pkt, 0, sizeof(*pkt));
	spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	list_add_tail(&pkt->list, &pSchedContext->cds_ol_rx_pkt_freeq);
	spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
}

/**
 * cds_alloc_ol_rx_pkt() - API to return next available cds message
 * @pSchedContext: Pointer to the global CDS Sched Context
 *
 * This api returns next available cds message buffer used for rx data
 * processing
 *
 * Return: Pointer to cds message buffer
 */
struct cds_ol_rx_pkt *cds_alloc_ol_rx_pkt(p_cds_sched_context pSchedContext)
{
	struct cds_ol_rx_pkt *pkt;

	spin_lock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	if (list_empty(&pSchedContext->cds_ol_rx_pkt_freeq)) {
		spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
		return NULL;
	}
	pkt = list_first_entry(&pSchedContext->cds_ol_rx_pkt_freeq,
			       struct cds_ol_rx_pkt, list);
	list_del(&pkt->list);
	spin_unlock_bh(&pSchedContext->cds_ol_rx_pkt_freeq_lock);
	return pkt;
}

/**
 * cds_indicate_rxpkt() - indicate rx data packet
 * @Arg: Pointer to the global CDS Sched Context
 * @pkt: CDS data message buffer
 *
 * This api enqueues the rx packet into ol_rx_thread_queue and notifies
 * cds_ol_rx_thread()
 *
 * Return: none
 */
void
cds_indicate_rxpkt(p_cds_sched_context pSchedContext,
		   struct cds_ol_rx_pkt *pkt)
{
	spin_lock_bh(&pSchedContext->ol_rx_queue_lock);
	list_add_tail(&pkt->list, &pSchedContext->ol_rx_thread_queue);
	spin_unlock_bh(&pSchedContext->ol_rx_queue_lock);
	set_bit(RX_POST_EVENT, &pSchedContext->ol_rx_event_flag);
	wake_up_interruptible(&pSchedContext->ol_rx_wait_queue);
}

/**
 * cds_wakeup_rx_thread() - wakeup rx thread
 * @Arg: Pointer to the global CDS Sched Context
 *
 * This api wake up cds_ol_rx_thread() to process pkt
 *
 * Return: none
 */
void
cds_wakeup_rx_thread(p_cds_sched_context pSchedContext)
{
	set_bit(RX_POST_EVENT, &pSchedContext->ol_rx_event_flag);
	wake_up_interruptible(&pSchedContext->ol_rx_wait_queue);
}

/**
 * cds_close_rx_thread() - close the Tlshim Rx thread
 * @p_cds_context: Pointer to the global CDS Context
 *
 * This api closes the Tlshim Rx thread:
 *
 * Return: qdf status
 */
QDF_STATUS cds_close_rx_thread(void *p_cds_context)
{
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: invoked", __func__);

	if (gp_cds_sched_context == NULL) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: gp_cds_sched_context == NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (!gp_cds_sched_context->ol_rx_thread)
		return QDF_STATUS_SUCCESS;

	/* Shut down Tlshim Rx thread */
	set_bit(RX_SHUTDOWN_EVENT, &gp_cds_sched_context->ol_rx_event_flag);
	set_bit(RX_POST_EVENT, &gp_cds_sched_context->ol_rx_event_flag);
	wake_up_interruptible(&gp_cds_sched_context->ol_rx_wait_queue);
	wait_for_completion(&gp_cds_sched_context->ol_rx_shutdown);
	gp_cds_sched_context->ol_rx_thread = NULL;
	cds_drop_rxpkt_by_staid(gp_cds_sched_context, WLAN_MAX_STA_COUNT);
	cds_free_ol_rx_pkt_freeq(gp_cds_sched_context);
	qdf_cpuhp_unregister(&gp_cds_sched_context->cpuhp_event_handle);

	return QDF_STATUS_SUCCESS;
} /* cds_close_rx_thread */

/**
 * cds_drop_rxpkt_by_staid() - api to drop pending rx packets for a sta
 * @pSchedContext: Pointer to the global CDS Sched Context
 * @staId: Station Id
 *
 * This api drops queued packets for a station, to drop all the pending
 * packets the caller has to send WLAN_MAX_STA_COUNT as staId.
 *
 * Return: none
 */
void cds_drop_rxpkt_by_staid(p_cds_sched_context pSchedContext, uint16_t staId)
{
	struct list_head local_list;
	struct cds_ol_rx_pkt *pkt, *tmp;
	qdf_nbuf_t buf, next_buf;

	INIT_LIST_HEAD(&local_list);
	spin_lock_bh(&pSchedContext->ol_rx_queue_lock);
	if (list_empty(&pSchedContext->ol_rx_thread_queue)) {
		spin_unlock_bh(&pSchedContext->ol_rx_queue_lock);
		return;
	}
	list_for_each_entry_safe(pkt, tmp, &pSchedContext->ol_rx_thread_queue,
								list) {
		if (pkt->staId == staId || staId == WLAN_MAX_STA_COUNT)
			list_move_tail(&pkt->list, &local_list);
	}
	spin_unlock_bh(&pSchedContext->ol_rx_queue_lock);

	list_for_each_entry_safe(pkt, tmp, &local_list, list) {
		list_del(&pkt->list);
		buf = pkt->Rxpkt;
		while (buf) {
			next_buf = qdf_nbuf_queue_next(buf);
			qdf_nbuf_free(buf);
			buf = next_buf;
		}
		cds_free_ol_rx_pkt(pSchedContext, pkt);
	}
}

/**
 * cds_rx_from_queue() - function to process pending Rx packets
 * @pSchedContext: Pointer to the global CDS Sched Context
 *
 * This api traverses the pending buffer list and calling the callback.
 * This callback would essentially send the packet to HDD.
 *
 * Return: none
 */
static void cds_rx_from_queue(p_cds_sched_context pSchedContext)
{
	struct cds_ol_rx_pkt *pkt;
	uint16_t sta_id;

	spin_lock_bh(&pSchedContext->ol_rx_queue_lock);
	while (!list_empty(&pSchedContext->ol_rx_thread_queue)) {
		pkt = list_first_entry(&pSchedContext->ol_rx_thread_queue,
				       struct cds_ol_rx_pkt, list);
		list_del(&pkt->list);
		spin_unlock_bh(&pSchedContext->ol_rx_queue_lock);
		sta_id = pkt->staId;
		pkt->callback(pkt->context, pkt->Rxpkt, sta_id);
		cds_free_ol_rx_pkt(pSchedContext, pkt);
		spin_lock_bh(&pSchedContext->ol_rx_queue_lock);
	}
	spin_unlock_bh(&pSchedContext->ol_rx_queue_lock);
}

/**
 * cds_ol_rx_thread() - cds main tlshim rx thread
 * @Arg: pointer to the global CDS Sched Context
 *
 * This api is the thread handler for Tlshim Data packet processing.
 *
 * Return: thread exit code
 */
static int cds_ol_rx_thread(void *arg)
{
	p_cds_sched_context pSchedContext = (p_cds_sched_context) arg;
	unsigned long pref_cpu = 0;
	bool shutdown = false;
	int status, i;

	set_user_nice(current, -1);
#ifdef MSM_PLATFORM
	set_wake_up_idle(true);
#endif

	/* Find the available cpu core other than cpu 0 and
	 * bind the thread
	 */
	/* Find the available cpu core other than cpu 0 and
	 * bind the thread */
	for_each_online_cpu(i) {
		if (i == 0)
			continue;
		pref_cpu = i;
			break;
	}

	if (pref_cpu != 0 && (!cds_set_cpus_allowed_ptr(current, pref_cpu)))
		affine_cpu = pref_cpu;

	if (!arg) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Bad Args passed", __func__);
		return 0;
	}

	complete(&pSchedContext->ol_rx_start_event);

	while (!shutdown) {
		status =
			wait_event_interruptible(pSchedContext->ol_rx_wait_queue,
						 test_bit(RX_POST_EVENT,
							  &pSchedContext->ol_rx_event_flag)
						 || test_bit(RX_SUSPEND_EVENT,
							     &pSchedContext->ol_rx_event_flag));
		if (status == -ERESTARTSYS)
			break;

		clear_bit(RX_POST_EVENT, &pSchedContext->ol_rx_event_flag);
		while (true) {
			if (test_bit(RX_SHUTDOWN_EVENT,
				     &pSchedContext->ol_rx_event_flag)) {
				clear_bit(RX_SHUTDOWN_EVENT,
					  &pSchedContext->ol_rx_event_flag);
				if (test_bit(RX_SUSPEND_EVENT,
					     &pSchedContext->ol_rx_event_flag)) {
					clear_bit(RX_SUSPEND_EVENT,
						  &pSchedContext->ol_rx_event_flag);
					complete
						(&pSchedContext->ol_suspend_rx_event);
				}
				QDF_TRACE(QDF_MODULE_ID_QDF,
					  QDF_TRACE_LEVEL_INFO,
					  "%s: Shutting down OL RX Thread",
					  __func__);
				shutdown = true;
				break;
			}
			cds_rx_from_queue(pSchedContext);

			if (test_bit(RX_SUSPEND_EVENT,
				     &pSchedContext->ol_rx_event_flag)) {
				clear_bit(RX_SUSPEND_EVENT,
					  &pSchedContext->ol_rx_event_flag);
				spin_lock(&pSchedContext->ol_rx_thread_lock);
				INIT_COMPLETION
					(pSchedContext->ol_resume_rx_event);
				complete(&pSchedContext->ol_suspend_rx_event);
				spin_unlock(&pSchedContext->ol_rx_thread_lock);
				wait_for_completion_interruptible
					(&pSchedContext->ol_resume_rx_event);
			}
			break;
		}
	}

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
		  "%s: Exiting CDS OL rx thread", __func__);
	complete_and_exit(&pSchedContext->ol_rx_shutdown, 0);

	return 0;
}
#endif

/**
 * cds_free_ol_mon_pkt_freeq() - free cds buffer free queue
 * @pSchedContext - pointer to the global CDS Sched Context
 *
 * This API does mem free of the buffers available in free cds buffer
 * queue which is used for mon Data processing.
 *
 * Return: none
 */
void cds_free_ol_mon_pkt_freeq(p_cds_sched_context pSchedContext)
{
	struct cds_ol_mon_pkt *pkt;

	spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	while (!list_empty(&pSchedContext->cds_ol_mon_pkt_freeq)) {
		pkt = list_entry((&pSchedContext->cds_ol_mon_pkt_freeq)->next,
				 typeof(*pkt), list);
		list_del(&pkt->list);
		spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		qdf_mem_free(pkt);
		spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	}
	spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
}

/**
 * cds_alloc_ol_mon_pkt_freeq() - Function to allocate free buffer queue
 * @pSchedContext - pointer to the global CDS Sched Context
 *
 * This API allocates CDS_MAX_OL_MON_PKT number of cds message buffers
 * which are used for mon data processing.
 *
 * Return: status of memory allocation
 */
static QDF_STATUS cds_alloc_ol_mon_pkt_freeq(p_cds_sched_context pSchedContext)
{
	struct cds_ol_mon_pkt *pkt, *tmp;
	int i;

	for (i = 0; i < CDS_MAX_OL_MON_PKT; i++) {
		pkt = qdf_mem_malloc(sizeof(*pkt));
		if (!pkt) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				  "%s Vos packet allocation for ol mon thread failed",
				  __func__);
			goto free;
		}
		spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		list_add_tail(&pkt->list, &pSchedContext->cds_ol_mon_pkt_freeq);
		spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	}

	return QDF_STATUS_SUCCESS;

free:
	spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	list_for_each_entry_safe(pkt, tmp, &pSchedContext->cds_ol_mon_pkt_freeq,
				 list) {
		list_del(&pkt->list);
		spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		qdf_mem_free(pkt);
		spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	}
	spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	return QDF_STATUS_E_NOMEM;
}

/**
 * cds_free_ol_mon_pkt() - api to release cds message to the freeq
 * This api returns the cds message used for mon data to the free queue
 * @pSchedContext: Pointer to the global CDS Sched Context
 * @pkt: CDS message buffer to be returned to free queue.
 *
 * Return: none
 */
void
cds_free_ol_mon_pkt(p_cds_sched_context pSchedContext,
		    struct cds_ol_mon_pkt *pkt)
{
	memset(pkt, 0, sizeof(*pkt));
	spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	list_add_tail(&pkt->list, &pSchedContext->cds_ol_mon_pkt_freeq);
	spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
}

/**
 * cds_alloc_ol_mon_pkt() - API to return next available cds message
 * @pSchedContext: Pointer to the global CDS Sched Context
 *
 * This api returns next available cds message buffer used for mon data
 * processing
 *
 * Return: Pointer to cds message buffer
 */
struct cds_ol_mon_pkt *cds_alloc_ol_mon_pkt(p_cds_sched_context pSchedContext)
{
	struct cds_ol_mon_pkt *pkt;

	spin_lock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	if (list_empty(&pSchedContext->cds_ol_mon_pkt_freeq)) {
		spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
		return NULL;
	}
	pkt = list_first_entry(&pSchedContext->cds_ol_mon_pkt_freeq,
			       struct cds_ol_mon_pkt, list);
	list_del(&pkt->list);
	spin_unlock_bh(&pSchedContext->cds_ol_mon_pkt_freeq_lock);
	return pkt;
}

/**
 * cds_indicate_monpkt() - indicate mon data packet
 * @Arg: Pointer to the global CDS Sched Context
 * @pkt: CDS data message buffer
 *
 * This api enqueues the mon packet into ol_mon_thread_queue and notifies
 * cds_ol_mon_thread()
 *
 * Return: none
 */
void
cds_indicate_monpkt(p_cds_sched_context pSchedContext,
		    struct cds_ol_mon_pkt *pkt)
{
	spin_lock_bh(&pSchedContext->ol_mon_queue_lock);
	list_add_tail(&pkt->list, &pSchedContext->ol_mon_thread_queue);
	spin_unlock_bh(&pSchedContext->ol_mon_queue_lock);
	set_bit(RX_POST_EVENT, &pSchedContext->ol_mon_event_flag);
	wake_up_interruptible(&pSchedContext->ol_mon_wait_queue);
}

/**
 * cds_wakeup_mon_thread() - wakeup mon thread
 * @Arg: Pointer to the global CDS Sched Context
 *
 * This api wake up cds_ol_mon_thread() to process pkt
 *
 * Return: none
 */
void
cds_wakeup_mon_thread(p_cds_sched_context pSchedContext)
{
	set_bit(RX_POST_EVENT, &pSchedContext->ol_mon_event_flag);
	wake_up_interruptible(&pSchedContext->ol_mon_wait_queue);
}

/**
 * cds_close_mon_thread() - close the Tlshim Rx thread
 * @p_cds_context: Pointer to the global CDS Context
 *
 * This api closes the Tlshim Rx thread:
 *
 * Return: qdf status
 */
QDF_STATUS cds_close_mon_thread(void *p_cds_context)
{
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: invoked", __func__);

	if (!gp_cds_sched_context) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: gp_cds_sched_context == NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (!gp_cds_sched_context->ol_mon_thread)
		return QDF_STATUS_SUCCESS;

	/* Shut down Tlshim Rx thread */
	set_bit(RX_SHUTDOWN_EVENT, &gp_cds_sched_context->ol_mon_event_flag);
	set_bit(RX_POST_EVENT, &gp_cds_sched_context->ol_mon_event_flag);
	wake_up_interruptible(&gp_cds_sched_context->ol_mon_wait_queue);
	wait_for_completion(&gp_cds_sched_context->ol_mon_shutdown);
	gp_cds_sched_context->ol_mon_thread = NULL;
	cds_drop_monpkt(gp_cds_sched_context);
	cds_free_ol_mon_pkt_freeq(gp_cds_sched_context);

	return QDF_STATUS_SUCCESS;
} /* cds_close_mon_thread */

/**
 * cds_drop_monpkt() - api to drop pending mon packets for a sta
 * @pschedcontext: Pointer to the global CDS Sched Context
 *
 * This api drops all queued packets for a station.
 *
 * Return: none
 */
void cds_drop_monpkt(p_cds_sched_context pschedcontext)
{
	struct list_head local_list;
	struct cds_ol_mon_pkt *pkt, *tmp;
	qdf_nbuf_t buf, next_buf;

	INIT_LIST_HEAD(&local_list);
	spin_lock_bh(&pschedcontext->ol_mon_queue_lock);
	if (list_empty(&pschedcontext->ol_mon_thread_queue)) {
		spin_unlock_bh(&pschedcontext->ol_mon_queue_lock);
		return;
	}
	list_for_each_entry_safe(pkt, tmp,
				 &pschedcontext->ol_mon_thread_queue,
				 list)
		list_move_tail(&pkt->list, &local_list);

	spin_unlock_bh(&pschedcontext->ol_mon_queue_lock);

	list_for_each_entry_safe(pkt, tmp, &local_list, list) {
		list_del(&pkt->list);
		buf = pkt->monpkt;
		while (buf) {
			next_buf = qdf_nbuf_queue_next(buf);
			qdf_nbuf_free(buf);
			buf = next_buf;
		}
		cds_free_ol_mon_pkt(pschedcontext, pkt);
	}
}

/**
 * cds_mon_from_queue() - function to process pending mon packets
 * @pschedcontext: Pointer to the global CDS Sched Context
 *
 * This api traverses the pending buffer list and calling the callback.
 * This callback would essentially send the packet to HDD.
 *
 * Return: none
 */
static void cds_mon_from_queue(p_cds_sched_context pschedcontext)
{
	struct cds_ol_mon_pkt *pkt;
	uint8_t vdev_id;
	uint8_t tid;

	spin_lock_bh(&pschedcontext->ol_mon_queue_lock);
	while (!list_empty(&pschedcontext->ol_mon_thread_queue)) {
		pkt = list_first_entry(&pschedcontext->ol_mon_thread_queue,
				       struct cds_ol_mon_pkt, list);
		list_del(&pkt->list);
		spin_unlock_bh(&pschedcontext->ol_mon_queue_lock);
		vdev_id = pkt->vdev_id;
		tid = pkt->tid;
		pkt->callback(pkt->context, pkt->monpkt, vdev_id,
			      tid, pkt->pkt_tx_status, pkt->pkt_format);
		cds_free_ol_mon_pkt(pschedcontext, pkt);
		spin_lock_bh(&pschedcontext->ol_mon_queue_lock);
	}
	spin_unlock_bh(&pschedcontext->ol_mon_queue_lock);
}

/**
 * cds_ol_mon_thread() - cds main tlshim mon thread
 * @Arg: pointer to the global CDS Sched Context
 *
 * This api is the thread handler for mon Data packet processing.
 *
 * Return: thread exit code
 */
static int cds_ol_mon_thread(void *arg)
{
	p_cds_sched_context pschedcontext = (p_cds_sched_context)arg;
	unsigned long pref_cpu = 0;
	bool shutdown = false;
	int status, i;

	if (!arg) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Bad Args passed", __func__);
		return 0;
	}

	set_user_nice(current, -1);
#ifdef MSM_PLATFORM
	set_wake_up_idle(true);
#endif

	/**
	 * Find the available cpu core other than cpu 0 and
	 * bind the thread
	 */
	for_each_online_cpu(i) {
		if (i == 0)
			continue;
		pref_cpu = i;
			break;
	}

	cds_set_cpus_allowed_ptr(current, pref_cpu);

	complete(&pschedcontext->ol_mon_start_event);

	while (!shutdown) {
		status =
		wait_event_interruptible(
				pschedcontext->ol_mon_wait_queue,
				test_bit(RX_POST_EVENT,
					 &pschedcontext->ol_mon_event_flag) ||
				test_bit(RX_SUSPEND_EVENT,
					 &pschedcontext->ol_mon_event_flag));
		if (status == -ERESTARTSYS)
			break;

		clear_bit(RX_POST_EVENT, &pschedcontext->ol_mon_event_flag);
		while (true) {
			if (test_bit(RX_SHUTDOWN_EVENT,
				     &pschedcontext->ol_mon_event_flag)) {
				clear_bit(RX_SHUTDOWN_EVENT,
					  &pschedcontext->ol_mon_event_flag);
				if (test_bit(
					RX_SUSPEND_EVENT,
					&pschedcontext->ol_mon_event_flag)) {
					clear_bit(
					RX_SUSPEND_EVENT,
					&pschedcontext->ol_mon_event_flag);
					complete
					(&pschedcontext->ol_suspend_mon_event);
				}
				QDF_TRACE(QDF_MODULE_ID_QDF,
					  QDF_TRACE_LEVEL_INFO,
					  "%s: Shutting down OL MON Thread",
					  __func__);
				shutdown = true;
				break;
			}
			cds_mon_from_queue(pschedcontext);

			if (test_bit(RX_SUSPEND_EVENT,
				     &pschedcontext->ol_mon_event_flag)) {
				clear_bit(RX_SUSPEND_EVENT,
					  &pschedcontext->ol_mon_event_flag);
				spin_lock(&pschedcontext->ol_mon_thread_lock);
				INIT_COMPLETION
					(pschedcontext->ol_resume_mon_event);
				complete(&pschedcontext->ol_suspend_mon_event);
				spin_unlock(&pschedcontext->ol_mon_thread_lock);
				wait_for_completion_interruptible
					(&pschedcontext->ol_resume_mon_event);
			}
			break;
		}
	}

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
		  "%s: Exiting CDS OL mon thread", __func__);
	complete_and_exit(&pschedcontext->ol_mon_shutdown, 0);

	return 0;
}

void cds_remove_timer_from_sys_msg(uint32_t timer_cookie)
{
	p_cds_msg_wrapper msg_wrapper = NULL;
	struct list_head *pos, *q;
	unsigned long flags;
	p_cds_mq_type sys_msgq;

	if (!gp_cds_sched_context) {
		cds_err("gp_cds_sched_context is null");
		return;
	}

	if (!gp_cds_sched_context->McThread) {
		cds_err("Cannot post message because MC thread is stopped");
		return;
	}

	sys_msgq = &gp_cds_sched_context->sysMcMq;
	/* No msg present in sys queue */
	if (cds_is_mq_empty(sys_msgq))
		return;

	spin_lock_irqsave(&sys_msgq->mqLock, flags);
	list_for_each_safe(pos, q, &sys_msgq->mqList) {
		msg_wrapper = list_entry(pos, cds_msg_wrapper, msgNode);

		if ((msg_wrapper->pVosMsg->type == SYS_MSG_ID_MC_TIMER) &&
		    (msg_wrapper->pVosMsg->bodyval == timer_cookie)) {
			/* return message to the Core */
			list_del(pos);
			spin_unlock_irqrestore(&sys_msgq->mqLock, flags);
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
				  "%s: removing timer message with cookie %d",
				  __func__, timer_cookie);
			cds_core_return_msg(gp_cds_sched_context->pVContext,
					    msg_wrapper);
			return;
		}

	}
	spin_unlock_irqrestore(&sys_msgq->mqLock, flags);
}

/**
 * cds_sched_close() - close the cds scheduler
 * @p_cds_context: Pointer to the global CDS Context
 *
 * This api closes the CDS Scheduler upon successful closing:
 *	- All the message queues are flushed
 *	- The Main Controller thread is closed
 *	- The Tx thread is closed
 *
 *
 * Return: qdf status
 */
QDF_STATUS cds_sched_close(void *p_cds_context)
{
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: invoked", __func__);

	if (gp_cds_sched_context == NULL) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: gp_cds_sched_context == NULL", __func__);
		return QDF_STATUS_E_FAILURE;
	}

	if (gp_cds_sched_context->McThread == 0)
		return QDF_STATUS_SUCCESS;

	/* shut down MC Thread */
	set_bit(MC_SHUTDOWN_EVENT, &gp_cds_sched_context->mcEventFlag);
	set_bit(MC_POST_EVENT, &gp_cds_sched_context->mcEventFlag);
	wake_up_interruptible(&gp_cds_sched_context->mcWaitQueue);
	/* Wait for MC to exit */
	wait_for_completion(&gp_cds_sched_context->McShutdown);
	gp_cds_sched_context->McThread = 0;

	/* Clean up message queues of MC thread */
	cds_sched_flush_mc_mqs(gp_cds_sched_context);

	/* Deinit all the queues */
	cds_sched_deinit_mqs(gp_cds_sched_context);

	cds_close_rx_thread(p_cds_context);

	if (cds_get_pktcap_mode_enable())
		cds_close_mon_thread(p_cds_context);

	gp_cds_sched_context = NULL;
	return QDF_STATUS_SUCCESS;
} /* cds_sched_close() */

/**
 * cds_sched_init_mqs() - initialize the cds scheduler message queues
 * @p_cds_sched_context: Pointer to the Scheduler Context.
 *
 * This api initializes the cds scheduler message queues.
 *
 * Return: QDF status
 */
QDF_STATUS cds_sched_init_mqs(p_cds_sched_context pSchedContext)
{
	QDF_STATUS vStatus = QDF_STATUS_SUCCESS;
	/* Now intialize all the message queues */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Initializing the WMA MC Message queue", __func__);
	vStatus = cds_mq_init(&pSchedContext->wmaMcMq);
	if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Failed to init WMA MC Message queue", __func__);
		QDF_ASSERT(0);
		return vStatus;
	}
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Initializing the PE MC Message queue", __func__);
	vStatus = cds_mq_init(&pSchedContext->peMcMq);
	if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Failed to init PE MC Message queue", __func__);
		QDF_ASSERT(0);
		return vStatus;
	}
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Initializing the SME MC Message queue", __func__);
	vStatus = cds_mq_init(&pSchedContext->smeMcMq);
	if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Failed to init SME MC Message queue", __func__);
		QDF_ASSERT(0);
		return vStatus;
	}
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s: Initializing the SYS MC Message queue", __func__);
	vStatus = cds_mq_init(&pSchedContext->sysMcMq);
	if (!QDF_IS_STATUS_SUCCESS(vStatus)) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: Failed to init SYS MC Message queue", __func__);
		QDF_ASSERT(0);
		return vStatus;
	}

	return QDF_STATUS_SUCCESS;
} /* cds_sched_init_mqs() */

/**
 * cds_sched_deinit_mqs() - Deinitialize the cds scheduler message queues
 * @p_cds_sched_context: Pointer to the Scheduler Context.
 *
 * Return: none
 */
void cds_sched_deinit_mqs(p_cds_sched_context pSchedContext)
{
	/* Now de-intialize all message queues */

	/* MC WMA */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s De-Initializing the WMA MC Message queue", __func__);
	cds_mq_deinit(&pSchedContext->wmaMcMq);
	/* MC PE */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s De-Initializing the PE MC Message queue", __func__);
	cds_mq_deinit(&pSchedContext->peMcMq);
	/* MC SME */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s De-Initializing the SME MC Message queue", __func__);
	cds_mq_deinit(&pSchedContext->smeMcMq);
	/* MC SYS */
	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO_HIGH,
		  "%s De-Initializing the SYS MC Message queue", __func__);
	cds_mq_deinit(&pSchedContext->sysMcMq);

} /* cds_sched_deinit_mqs() */

/**
 * cds_sched_flush_mc_mqs() - flush all the MC thread message queues
 * @pSchedContext: Pointer to global cds context
 *
 * Return: none
 */
void cds_sched_flush_mc_mqs(p_cds_sched_context pSchedContext)
{
	p_cds_msg_wrapper pMsgWrapper = NULL;
	p_cds_contextType cds_ctx;

	/* Here each of the MC thread MQ shall be drained and returned to the
	 * Core. Before returning a wrapper to the Core, the CDS message shall
	 * be freed first
	 */
	QDF_TRACE(QDF_MODULE_ID_QDF,
		  QDF_TRACE_LEVEL_DEBUG,
		  ("Flushing the MC Thread message queue"));

	if (NULL == pSchedContext) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: pSchedContext is NULL", __func__);
		return;
	}

	cds_ctx = (p_cds_contextType) (pSchedContext->pVContext);
	if (NULL == cds_ctx) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: cds_ctx is NULL", __func__);
		return;
	}

	/* Flush the SYS Mq */
	while (NULL != (pMsgWrapper = cds_mq_get(&pSchedContext->sysMcMq))) {
		QDF_TRACE(QDF_MODULE_ID_QDF,
			  QDF_TRACE_LEVEL_DEBUG,
			  "%s: Freeing MC SYS message type %d ", __func__,
			  pMsgWrapper->pVosMsg->type);
		cds_core_return_msg(pSchedContext->pVContext, pMsgWrapper);
	}
	/* Flush the WMA Mq */
	while (NULL != (pMsgWrapper = cds_mq_get(&pSchedContext->wmaMcMq))) {
		if (pMsgWrapper->pVosMsg != NULL) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_DEBUG,
				  "%s: Freeing MC WMA MSG message type %d",
				  __func__, pMsgWrapper->pVosMsg->type);

			wma_mc_discard_msg(pMsgWrapper->pVosMsg);
		}
		cds_core_return_msg(pSchedContext->pVContext, pMsgWrapper);
	}

	/* Flush the PE Mq */
	while (NULL != (pMsgWrapper = cds_mq_get(&pSchedContext->peMcMq))) {
		QDF_TRACE(QDF_MODULE_ID_QDF,
			  QDF_TRACE_LEVEL_DEBUG,
			  "%s: Freeing MC PE MSG message type %d", __func__,
			  pMsgWrapper->pVosMsg->type);
		pe_free_msg(cds_ctx->pMACContext,
			    (tSirMsgQ *) pMsgWrapper->pVosMsg);
		cds_core_return_msg(pSchedContext->pVContext, pMsgWrapper);
	}
	/* Flush the SME Mq */
	while (NULL != (pMsgWrapper = cds_mq_get(&pSchedContext->smeMcMq))) {
		QDF_TRACE(QDF_MODULE_ID_QDF,
			  QDF_TRACE_LEVEL_DEBUG,
			  "%s: Freeing MC SME MSG message type %d", __func__,
			  pMsgWrapper->pVosMsg->type);
		sme_free_msg(cds_ctx->pMACContext, pMsgWrapper->pVosMsg);
		cds_core_return_msg(pSchedContext->pVContext, pMsgWrapper);
	}
} /* cds_sched_flush_mc_mqs() */

/**
 * get_cds_sched_ctxt() - get cds scheduler context
 *
 * Return: none
 */
p_cds_sched_context get_cds_sched_ctxt(void)
{
	/* Make sure that Vos Scheduler context has been initialized */
	if (gp_cds_sched_context == NULL)
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s: gp_cds_sched_context == NULL", __func__);

	return gp_cds_sched_context;
}

/**
 * cds_ssr_protect_init() - initialize ssr protection debug functionality
 *
 * Return:
 *        void
 */
void cds_ssr_protect_init(void)
{
	int i = 0;

	spin_lock_init(&ssr_protect_lock);

	while (i < MAX_SSR_PROTECT_LOG) {
		ssr_protect_log[i].func = NULL;
		ssr_protect_log[i].free = true;
		ssr_protect_log[i].pid =  0;
		i++;
	}

	INIT_LIST_HEAD(&shutdown_notifier_head);
}

/**
 * cds_print_external_threads() - print external threads stuck in driver
 *
 * Return:
 *        void
 */
void cds_print_external_threads(void)
{
	int i = 0;
	unsigned long irq_flags;

	spin_lock_irqsave(&ssr_protect_lock, irq_flags);

	while (i < MAX_SSR_PROTECT_LOG) {
		if (!ssr_protect_log[i].free) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				  "PID %d is executing %s",
				  ssr_protect_log[i].pid,
				  ssr_protect_log[i].func);
		}
		i++;
	}

	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);
}

/**
 * cds_ssr_protect() - start ssr protection
 * @caller_func: name of calling function.
 *
 * This function is called to keep track of active driver entry points
 *
 * Return: none
 */
void cds_ssr_protect(const char *caller_func)
{
	int count;
	int i = 0;
	bool status = false;
	unsigned long irq_flags;

	count = atomic_inc_return(&ssr_protect_entry_count);

	spin_lock_irqsave(&ssr_protect_lock, irq_flags);

	while (i < MAX_SSR_PROTECT_LOG) {
		if (ssr_protect_log[i].free) {
			ssr_protect_log[i].func = caller_func;
			ssr_protect_log[i].free = false;
			ssr_protect_log[i].pid = current->pid;
			status = true;
			break;
		}
		i++;
	}

	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);

	/*
	 * Dump the protect log at intervals if count is consistently growing.
	 * Long running functions should tend to dominate the protect log, so
	 * hopefully, dumping at multiples of log size will prevent spamming the
	 * logs while telling us which calls are taking a long time to finish.
	 */
	if (count >= MAX_SSR_PROTECT_LOG && count % MAX_SSR_PROTECT_LOG == 0) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "Protect Log overflow; Dumping contents:");
		cds_print_external_threads();
	}

	if (!status)
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s can not be protected; PID:%d, entry_count:%d",
			  caller_func, current->pid, count);
}

/**
 * cds_ssr_unprotect() - stop ssr protection
 * @caller_func: name of calling function.
 *
 * Return: none
 */
void cds_ssr_unprotect(const char *caller_func)
{
	int count;
	int i = 0;
	bool status = false;
	unsigned long irq_flags;

	count = atomic_dec_return(&ssr_protect_entry_count);

	spin_lock_irqsave(&ssr_protect_lock, irq_flags);

	while (i < MAX_SSR_PROTECT_LOG) {
		if (!ssr_protect_log[i].free) {
			if ((ssr_protect_log[i].pid == current->pid) &&
			     !strcmp(ssr_protect_log[i].func, caller_func)) {
				ssr_protect_log[i].func = NULL;
				ssr_protect_log[i].free = true;
				ssr_protect_log[i].pid =  0;
				status = true;
				break;
			}
		}
		i++;
	}

	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);

	if (!status)
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "%s was not protected; PID:%d, entry_count:%d",
			  caller_func, current->pid, count);
}

/**
 * cds_shutdown_notifier_register() - Register for shutdown notification
 * @cb          : Call back to be called
 * @priv        : Private pointer to be passed back to call back
 *
 * During driver remove or shutdown (recovery), external threads might be stuck
 * waiting on some event from firmware at lower layers. Remove or shutdown can't
 * proceed till the thread completes to avoid any race condition. Call backs can
 * be registered here to get early notification of remove or shutdown so that
 * waiting thread can be unblocked and hence remove or shutdown can proceed
 * further as waiting there may not make sense when FW may already have been
 * down.
 *
 * This is intended for early notification of remove() or shutdown() only so
 * that lower layers can take care of stuffs like external waiting thread.
 *
 * Return: CDS status
 */
QDF_STATUS cds_shutdown_notifier_register(void (*cb)(void *priv), void *priv)
{
	struct shutdown_notifier *notifier;
	unsigned long irq_flags;

	notifier = qdf_mem_malloc(sizeof(*notifier));

	if (notifier == NULL)
		return QDF_STATUS_E_NOMEM;

	/*
	 * This logic can be simpilfied if there is separate state maintained
	 * for shutdown and reinit. Right now there is only recovery in progress
	 * state and it doesn't help to check against it as during reinit some
	 * of the modules may need to register the call backs.
	 * For now this logic added to avoid notifier registration happen while
	 * this function is trying to call the call back with the notification.
	 */
	spin_lock_irqsave(&ssr_protect_lock, irq_flags);
	if (notifier_state == NOTIFIER_STATE_NOTIFYING) {
		spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);
		qdf_mem_free(notifier);
		return -EINVAL;
	}

	notifier->cb = cb;
	notifier->priv = priv;

	list_add_tail(&notifier->list, &shutdown_notifier_head);
	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);

	return 0;
}

/**
 * cds_shutdown_notifier_purge() - Purge all the notifiers
 *
 * Shutdown notifiers are added to provide the early notification of remove or
 * shutdown being initiated. Adding this API to purge all the registered call
 * backs as they are not useful any more while all the lower layers are being
 * shutdown.
 *
 * Return: None
 */
void cds_shutdown_notifier_purge(void)
{
	struct shutdown_notifier *notifier, *temp;
	unsigned long irq_flags;

	spin_lock_irqsave(&ssr_protect_lock, irq_flags);
	list_for_each_entry_safe(notifier, temp,
				 &shutdown_notifier_head, list) {
		list_del(&notifier->list);
		spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);

		qdf_mem_free(notifier);

		spin_lock_irqsave(&ssr_protect_lock, irq_flags);
	}

	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);
}

/**
 * cds_shutdown_notifier_call() - Call shutdown notifier call back
 *
 * Call registered shutdown notifier call back to indicate about remove or
 * shutdown.
 */
void cds_shutdown_notifier_call(void)
{
	struct shutdown_notifier *notifier;
	unsigned long irq_flags;

	spin_lock_irqsave(&ssr_protect_lock, irq_flags);
	notifier_state = NOTIFIER_STATE_NOTIFYING;

	list_for_each_entry(notifier, &shutdown_notifier_head, list) {
		spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);

		notifier->cb(notifier->priv);

		spin_lock_irqsave(&ssr_protect_lock, irq_flags);
	}

	notifier_state = NOTIFIER_STATE_NONE;
	spin_unlock_irqrestore(&ssr_protect_lock, irq_flags);
}

/**
 * cds_wait_for_external_threads_completion() - wait for external threads
 *					completion before proceeding further
 * @caller_func: name of calling function.
 *
 * Return: true if there is no active entry points in driver
 *	   false if there is at least one active entry in driver
 */
bool cds_wait_for_external_threads_completion(const char *caller_func)
{
	int count = MAX_SSR_WAIT_ITERATIONS;
	int r;

	while (count) {

		r = atomic_read(&ssr_protect_entry_count);

		if (!r)
			break;

		if (--count) {
			QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
				  "%s: Waiting for %d active entry points to exit",
				  __func__, r);
			msleep(SSR_WAIT_SLEEP_TIME);
			if (count & 0x1) {
				QDF_TRACE(QDF_MODULE_ID_QDF,
					QDF_TRACE_LEVEL_ERROR,
					"%s: in middle of waiting for active entry points:",
					__func__);
				cds_print_external_threads();
			}
		}
	}

	/* at least one external thread is executing */
	if (!count) {
		QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_ERROR,
			  "Timed-out waiting for active entry points:");
		cds_print_external_threads();
		return false;
	}

	QDF_TRACE(QDF_MODULE_ID_QDF, QDF_TRACE_LEVEL_INFO,
		  "Allowing SSR/Driver unload for %s", caller_func);

	return true;
}

int cds_return_external_threads_count(void)
{
	return  atomic_read(&ssr_protect_entry_count);
}

/**
 * cds_get_gfp_flags(): get GFP flags
 *
 * Based on the scheduled context, return GFP flags
 * Return: gfp flags
 */
int cds_get_gfp_flags(void)
{
	int flags = GFP_KERNEL;

	if (in_interrupt() || in_atomic() || irqs_disabled())
		flags = GFP_ATOMIC;

	return flags;
}
