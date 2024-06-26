/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <prof.h>
#include <plugin.h>
#include <pthread.h>
#include <rpmb.h>
#include <nvme_rpmb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>
#include <teec_trace.h>
#include <tee_socket.h>
#include <tee_supp_fs.h>
#include <tee_supplicant.h>
#include <unistd.h>
#include <time.h>
#include "optee_msg_supplicant.h"
#include <sys/syscall.h>
#include <linux/sched.h>

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#include <linux/tee.h>

#define RPC_NUM_PARAMS	5

#define RPC_BUF_SIZE	(sizeof(struct tee_iocl_supp_send_arg) + \
			 RPC_NUM_PARAMS * sizeof(struct tee_ioctl_param))


#define gettid() ((pid_t)syscall(SYS_gettid))

static long long getMilliseconds() {
    struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
    // 将秒和纳秒转换为纳秒级时间戳
    long long timestamp_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;
	return timestamp_ns;
}

char **ta_path;
char *ta_path_str;

union tee_rpc_invoke {
	uint64_t buf[(RPC_BUF_SIZE - 1) / sizeof(uint64_t) + 1];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};

struct tee_shm {
	int id;
	void *p;
	size_t size;
	bool registered;
	int fd;
	struct tee_shm *next;
};

struct thread_arg {
	int fd;
	uint32_t gen_caps;
	bool abort;
	size_t num_waiters;
	pthread_mutex_t mutex;
};

struct param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

static pthread_mutex_t shm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct tee_shm *shm_head;

struct tee_supplicant_params supplicant_params = {
	.ta_dir = "optee_armtz",
#ifdef TEE_PLUGIN_LOAD_PATH
	.plugin_load_path = TEE_PLUGIN_LOAD_PATH,
#endif
	.fs_parent_path  = TEE_FS_PARENT_PATH,
};

static void *thread_main(void *a);

static size_t num_waiters_inc(struct thread_arg *arg)
{
	size_t ret = 0;

	tee_supp_mutex_lock(&arg->mutex);
	arg->num_waiters++;
	assert(arg->num_waiters);
	ret = arg->num_waiters;

	printf("| %lld | %4d | %d | num_waiters_inc---num_waiters : %ld\n", getMilliseconds(), gettid(), sched_getcpu(), ret);

	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static size_t num_waiters_dec(struct thread_arg *arg)
{
	size_t ret = 0;

	tee_supp_mutex_lock(&arg->mutex);
	assert(arg->num_waiters);
	arg->num_waiters--;
	ret = arg->num_waiters;

	printf("| %lld | %4d | %d | num_waiters_dec---num_waiters : %ld\n", getMilliseconds(), gettid(), sched_getcpu(), ret);

	tee_supp_mutex_unlock(&arg->mutex);

	return ret;
}

static void *paged_aligned_alloc(size_t sz)
{
	void *p = NULL;

	if (!posix_memalign(&p, sysconf(_SC_PAGESIZE), sz))
		return p;

	return NULL;
}

static int get_value(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, struct param_value **value)
{
	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		*value = (void *)&params[idx].a;
		return 0;
	default:
		return -1;
	}
}

static struct tee_shm *find_tshm(int id)
{
	struct tee_shm *tshm = NULL;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	while (tshm && tshm->id != id)
		tshm = tshm->next;

	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static struct tee_shm *pop_tshm(int id)
{
	struct tee_shm *tshm = NULL;
	struct tee_shm *prev = NULL;

	tee_supp_mutex_lock(&shm_mutex);

	tshm = shm_head;
	if (!tshm)
		goto out;

	if (tshm->id == id) {
		shm_head = tshm->next;
		goto out;
	}

	do {
		prev = tshm;
		tshm = tshm->next;
		if (!tshm)
			goto out;
	} while (tshm->id != id);
	prev->next = tshm->next;

out:
	tee_supp_mutex_unlock(&shm_mutex);

	return tshm;
}

static void push_tshm(struct tee_shm *tshm)
{
	tee_supp_mutex_lock(&shm_mutex);

	tshm->next = shm_head;
	shm_head = tshm;

	tee_supp_mutex_unlock(&shm_mutex);
}

/* Get parameter allocated by secure world */
static int get_param(size_t num_params, struct tee_ioctl_param *params,
		     const uint32_t idx, TEEC_SharedMemory *shm)
{
	struct tee_shm *tshm = NULL;
	size_t offs = 0;
	size_t sz = 0;

	if (idx >= num_params)
		return -1;

	switch (params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return -1;
	}

	memset(shm, 0, sizeof(*shm));

	tshm = find_tshm(MEMREF_SHM_ID(params + idx));
	if (!tshm) {
		/*
		 * It doesn't make sense to query required size of an
		 * input buffer.
		 */
		if ((params[idx].attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) ==
		    TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)
			return -1;

		/*
		 * Buffer isn't found, the caller is querying required size
		 * of the buffer.
		 */
		return 0;
	}

	sz = MEMREF_SIZE(params + idx);
	offs = MEMREF_SHM_OFFS(params + idx);
	if ((sz + offs) < sz)
		return -1;
	if ((sz + offs) > tshm->size)
		return -1;

	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm->size = sz;
	shm->id = MEMREF_SHM_ID(params + idx);
	shm->buffer = (uint8_t *)tshm->p + offs;

	return 0;
}

static void uuid_from_octets(TEEC_UUID *d, const uint8_t s[TEE_IOCTL_UUID_LEN])
{
	d->timeLow = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
	d->timeMid = (s[4] << 8) | s[5];
	d->timeHiAndVersion = (s[6] << 8) | s[7];
	memcpy(d->clockSeqAndNode, s + 8, sizeof(d->clockSeqAndNode));
}

static uint32_t load_ta(size_t num_params, struct tee_ioctl_param *params)
{
	int ta_found = 0;
	size_t size = 0;
	struct param_value *val_cmd = NULL;
	TEEC_UUID uuid;
	TEEC_SharedMemory shm_ta;

	memset(&uuid, 0, sizeof(uuid));
	memset(&shm_ta, 0, sizeof(shm_ta));

	if (num_params != 2 || get_value(num_params, params, 0, &val_cmd) ||
	    get_param(num_params, params, 1, &shm_ta)){
			printf("\n\n\nload_ta error!!!\n\n\n");
			EMSG("\n\n\nload_ta error111!!!\n\n\n");
			IMSG("\n\n\nload_ta error222!!!\n\n\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

	uuid_from_octets(&uuid, (void *)val_cmd);

	size = shm_ta.size;
	ta_found = TEECI_LoadSecureModule(supplicant_params.ta_dir, &uuid, shm_ta.buffer, &size);
	if (ta_found != TA_BINARY_FOUND) {
		EMSG("  TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	MEMREF_SIZE(params + 1) = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (shm_ta.buffer && size > shm_ta.size)
		return TEEC_ERROR_SHORT_BUFFER;

	return TEEC_SUCCESS;
}

static struct tee_shm *alloc_shm(int fd, size_t size)
{
	struct tee_shm *shm = NULL;
	struct tee_ioctl_shm_alloc_data data;

	memset(&data, 0, sizeof(data));

	shm = calloc(1, sizeof(*shm));
	if (!shm)
		return NULL;

	data.size = size;
	shm->fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	if (shm->fd < 0) {
		free(shm);
		return NULL;
	}

	shm->p = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      shm->fd, 0);
	if (shm->p == (void *)MAP_FAILED) {
		close(shm->fd);
		free(shm);
		return NULL;
	}

	shm->id = data.id;
	shm->registered = false;
	return shm;
}

static struct tee_shm *register_local_shm(int fd, size_t size)
{
	struct tee_shm *shm = NULL;
	void *buf = NULL;
	struct tee_ioctl_shm_register_data data;

	memset(&data, 0, sizeof(data));

	buf = paged_aligned_alloc(size);
	if (!buf)
		return NULL;

	shm = calloc(1, sizeof(*shm));
	if (!shm) {
		free(buf);
		return NULL;
	}

	data.addr = (uintptr_t)buf;
	data.length = size;

	shm->fd = ioctl(fd, TEE_IOC_SHM_REGISTER, &data);
	if (shm->fd < 0) {
		free(shm);
		free(buf);
		return NULL;
	}

	shm->p = buf;
	shm->registered = true;
	shm->id = data.id;

	return shm;
}

static uint32_t process_alloc(struct thread_arg *arg, size_t num_params,
			      struct tee_ioctl_param *params)
{
	struct param_value *val = NULL;
	struct tee_shm *shm = NULL;

	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (arg->gen_caps & TEE_GEN_CAP_REG_MEM)
		shm = register_local_shm(arg->fd, val->b);
	else
		shm = alloc_shm(arg->fd, val->b);

	if (!shm)
		return TEEC_ERROR_OUT_OF_MEMORY;

	shm->size = val->b;
	val->c = shm->id;
	push_tshm(shm);

	return TEEC_SUCCESS;
}

static uint32_t process_free(size_t num_params, struct tee_ioctl_param *params)
{
	struct param_value *val = NULL;
	struct tee_shm *shm = NULL;
	int id = 0;

	if (num_params != 1 || get_value(num_params, params, 0, &val))
		return TEEC_ERROR_BAD_PARAMETERS;

	id = val->b;

	shm = pop_tshm(id);
	if (!shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	close(shm->fd);
	if (shm->registered) {
		free(shm->p);
	} else  {
		if (munmap(shm->p, shm->size) != 0) {
			EMSG("munmap(%p, %zu) failed - Error = %s",
			     shm->p, shm->size, strerror(errno));
			free(shm);
			return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	free(shm);
	return TEEC_SUCCESS;
}



/* How many device sequence numbers will be tried before giving up */
#define MAX_DEV_SEQ	10

static int open_dev(const char *devname, uint32_t *gen_caps)
{
	int fd = 0;
	struct tee_ioctl_version_data vers;

	memset(&vers, 0, sizeof(vers));

	fd = open(devname, O_RDWR);
	if (fd < 0)
		return -1;

	if (ioctl(fd, TEE_IOC_VERSION, &vers))
		goto err;

	/* Only OP-TEE supported */
	if (vers.impl_id != TEE_IMPL_ID_OPTEE)
		goto err;

	if (gen_caps)
		*gen_caps = vers.gen_caps;

	DMSG("using device \"%s\"", devname);
	return fd;
err:
	close(fd);
	return -1;
}

static int get_dev_fd(uint32_t *gen_caps)
{
	int fd = 0;
	char name[PATH_MAX] = { 0 };
	size_t n = 0;

	for (n = 0; n < MAX_DEV_SEQ; n++) {
		snprintf(name, sizeof(name), "/dev/teepriv%zu", n);
		fd = open_dev(name, gen_caps);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

static int usage(int status)
{
	fprintf(stderr, "Usage: tee-supplicant [options] [<device-name>]\n");
	fprintf(stderr, "\t-h, --help: this help\n");
	fprintf(stderr, "\t-d, --daemonize: run as a daemon (fork and return "
			"after child has opened the TEE device or on error)\n");
	fprintf(stderr, "\t-f, --fs-parent-path: secure fs parent path [%s]\n",
			supplicant_params.fs_parent_path);
	fprintf(stderr, "\t-t, --ta-dir: TAs dirname under %s [%s]\n", TEEC_LOAD_PATH,
			supplicant_params.ta_dir);
	fprintf(stderr, "\t-p, --plugin-path: plugin load path [%s]\n",
			supplicant_params.plugin_load_path);
	fprintf(stderr, "\t-r, --rpmb-cid: RPMB device identification register "
			"(CID) in hexadecimal\n");
	return status;
}

static uint32_t process_rpmb(size_t num_params, struct tee_ioctl_param *params)
{
	TEEC_SharedMemory req;
	TEEC_SharedMemory rsp;

	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	if (get_param(num_params, params, 0, &req) ||
	    get_param(num_params, params, 1, &rsp))
		return TEEC_ERROR_BAD_PARAMETERS;

	return rpmb_process_request(req.buffer, req.size, rsp.buffer, rsp.size);
}

static uint32_t process_nvme_rpmb(size_t num_params, struct tee_ioctl_param *params)
{
	TEEC_SharedMemory req;
	TEEC_SharedMemory rsp;

	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	if (get_param(num_params, params, 0, &req) ||
	    get_param(num_params, params, 1, &rsp))
		return TEEC_ERROR_BAD_PARAMETERS;

	return nvme_rpmb_process_request(req.buffer, req.size, rsp.buffer, rsp.size);
}

static bool read_request(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	memset(&data, 0, sizeof(data));

	data.buf_ptr = (uintptr_t)request;
	data.buf_len = sizeof(*request);

	printf("| %lld | %4d | %d | read_request---before ioctl\n", getMilliseconds(), gettid(), sched_getcpu());

	if (ioctl(fd, TEE_IOC_SUPPL_RECV, &data)) {
		EMSG("TEE_IOC_SUPPL_RECV: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool write_response(int fd, union tee_rpc_invoke *request)
{
	struct tee_ioctl_buf_data data;

	memset(&data, 0, sizeof(data));

	data.buf_ptr = (uintptr_t)&request->send;
	data.buf_len = sizeof(struct tee_iocl_supp_send_arg) +
		       sizeof(struct tee_ioctl_param) *
				(__u64)request->send.num_params;
	
	printf("| %lld | %4d | %d | write_response---before ioctl\n", getMilliseconds(), gettid(), sched_getcpu());

	if (ioctl(fd, TEE_IOC_SUPPL_SEND, &data)) {
		EMSG("TEE_IOC_SUPPL_SEND: %s", strerror(errno));
		return false;
	}
	return true;
}

static bool find_params(union tee_rpc_invoke *request, uint32_t *func,
			size_t *num_params, struct tee_ioctl_param **params,
			size_t *num_meta)
{
	struct tee_ioctl_param *p = NULL;
	size_t n = 0;

	p = (struct tee_ioctl_param *)(&request->recv + 1);

	/* Skip meta parameters in the front */
	for (n = 0; n < request->recv.num_params; n++)
		if (!(p[n].attr & TEE_IOCTL_PARAM_ATTR_META))
			break;

	*func = request->recv.func;
	*num_params = request->recv.num_params - n;
	*params = p + n;
	*num_meta = n;

	/* Make sure that no meta parameters follows a non-meta parameter */
	for (; n < request->recv.num_params; n++) {
		if (p[n].attr & TEE_IOCTL_PARAM_ATTR_META) {
			EMSG("Unexpected meta parameter");
			return false;
		}
	}

	return true;
}

static bool spawn_thread(struct thread_arg *arg)
{
	int e = 0;
	pthread_t tid;

	memset(&tid, 0, sizeof(tid));

	DMSG("Spawning a new thread");

	printf("| %lld | %4d | %d | spawn_thread---start %lu\n", getMilliseconds(), gettid(), sched_getcpu(), pthread_self());

	/*
	 * Increase number of waiters now to avoid starting another thread
	 * before this thread has been scheduled.
	 */
	num_waiters_inc(arg);

	e = pthread_create(&tid, NULL, thread_main, arg);
	if (e) {
		EMSG("pthread_create: %s", strerror(e));
		num_waiters_dec(arg);
		return false;
	}

	e = pthread_detach(tid);
	if (e)
		EMSG("pthread_detach: %s", strerror(e));

	printf("| %lld | %4d | %d | spawn_thread---tid : %lu\n", getMilliseconds(), gettid(), sched_getcpu(), tid);

	return true;
}

static bool process_one_request(struct thread_arg *arg)
{
	printf("| %lld | %4d | %d | process_one_request---start\n", getMilliseconds(), gettid(), sched_getcpu());

	size_t num_params = 0;
	size_t num_meta = 0;
	struct tee_ioctl_param *params = NULL;
	uint32_t func = 0;
	uint32_t ret = 0;
	union tee_rpc_invoke request;

	memset(&request, 0, sizeof(request));

	DMSG("looping");
	request.recv.num_params = RPC_NUM_PARAMS;

	/* Let it be known that we can deal with meta parameters */
	params = (struct tee_ioctl_param *)(&request.send + 1);
	params->attr = TEE_IOCTL_PARAM_ATTR_META;

	num_waiters_inc(arg);

	if (!read_request(arg->fd, &request)){
		return false;
	}

	printf("| %lld | %4d | %d | process_one_request---after read_request\n", getMilliseconds(), gettid(), sched_getcpu());

	if (!find_params(&request, &func, &num_params, &params, &num_meta)){

		printf("| %lld | %4d | %d | process_one_request---!find_params\n", getMilliseconds(), gettid(), sched_getcpu());

		return false;
	}

	if (num_meta && !num_waiters_dec(arg) && !spawn_thread(arg)){
		
		printf("| %lld | %4d | %d | process_one_request---num_meta false\n", getMilliseconds(), gettid(), sched_getcpu());

		return false;
	}

	switch (func) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_LOAD_TA\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = load_ta(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_FS\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = tee_supp_fs_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_RPMB:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_RPMB\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = process_rpmb(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_SHM_ALLOC\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = process_alloc(arg, num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_SHM_FREE\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = process_free(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_GPROF:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_GPROF\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = prof_process(num_params, params, "gmon-");
		break;
	case OPTEE_MSG_RPC_CMD_SOCKET:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_SOCKET\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = tee_socket_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_FTRACE:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_FTRACE\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = prof_process(num_params, params, "ftrace-");
		break;
	case OPTEE_MSG_RPC_CMD_PLUGIN:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_PLUGIN\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = plugin_process(num_params, params);
		break;
	case OPTEE_MSG_RPC_CMD_NVME_RPMB:
		printf("| %lld | %4d | %d | process_one_request---OPTEE_MSG_RPC_CMD_NVME_RPMB\n", getMilliseconds(), gettid(), sched_getcpu());
		ret = process_nvme_rpmb(num_params, params);
		break;
	default:
		printf("| %lld | %4d | %d | process_one_request---default\n", getMilliseconds(), gettid(), sched_getcpu());

		EMSG("Cmd [0x%" PRIx32 "] not supported", func);
		/* Not supported. */
		ret = TEEC_ERROR_NOT_SUPPORTED;
		break;
	}

	request.send.ret = ret;
	printf("| %lld | %4d | %d | process_one_request---before write_response\n", getMilliseconds(), gettid(), sched_getcpu());
	return write_response(arg->fd, &request);
}

static void *thread_main(void *a)
{
	struct thread_arg *arg = a;

	printf("| %lld | %4d | %d | thread_main---start\n", getMilliseconds(), gettid(), sched_getcpu());

	/*
	 * Now that this thread has been scheduled, compensate for the
	 * initial increase in spawn_thread() before.
	 */
	num_waiters_dec(arg);

	while (!arg->abort) {
		if (!process_one_request(arg)){
			printf("| %lld | %4d | %d | thread_main---arg->abort == true\n", getMilliseconds(), gettid(), sched_getcpu());
			arg->abort = true;
		}
		else{
			printf("| %lld | %4d | %d | thread_main---arg->abort == false\n", getMilliseconds(), gettid(), sched_getcpu());
		}
	}

	printf("| %lld | %4d | %d | thread_main---end\n", getMilliseconds(), gettid(), sched_getcpu());

	return NULL;
}

#define TEEC_TEST_LOAD_PATH "/foo:/bar::/baz"

static void set_ta_path(void)
{
	char *p = NULL;
	char *saveptr = NULL;
	const char *path = (char *)
#ifdef TEEC_TEST_LOAD_PATH
		TEEC_TEST_LOAD_PATH ":"
#endif
		TEEC_LOAD_PATH;
	size_t n = 0;

	ta_path_str = strdup(path);
	if (!ta_path_str)
		goto err;

	p = ta_path_str;
	while (strtok_r(p, ":", &saveptr)) {
		p = NULL;
		n++;
	}
	n++; /* NULL terminator */

	ta_path = malloc(n * sizeof(char *));
	if (!ta_path)
		goto err;

	n = 0;
	strcpy(ta_path_str, path);
	p = ta_path_str;
	while ((ta_path[n++] = strtok_r(p, ":", &saveptr)))
	       p = NULL;

	return;
err:
	EMSG("out of memory");
	exit(EXIT_FAILURE);
}

/*
 * Similar to the standard libc function daemon(0, 0) but the parent process
 * issues a blocking read on pipefd[0] before exiting.
 * Returns 0 on success, <0 on error.
 */
static int make_daemon(int pipefd[2])
{
	int fd = 0;
	char c = 0;
	int n = 0;

	switch (fork()) {
	case -1:
		return -1;
	case 0:
		/* In child */
		close(pipefd[0]);
		break;
	default:
		/* In parent */
		close(pipefd[1]);
		n = read(pipefd[0], &c, 1);
		close(pipefd[0]);
		if (!n) {
			/*
			 * Nothing has been read: child has closed without
			 * writing (either exited on error or crashed)
			 */
			return -1;
		}
		/* Child is done with the opening of the TEE device */
		_exit(EXIT_SUCCESS);
	}

	if (setsid() < 0)
		return -2;

	if (chdir("/") < 0)
		return -3;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		return -4;
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	struct thread_arg arg = { .fd = -1 };
	int pipefd[2] = { 0, };
	bool daemonize = false;
	char *dev = NULL;
	int e = 0;
	int long_index = 0;
	int opt = 0;

	e = pthread_mutex_init(&arg.mutex, NULL);
	if (e) {
		EMSG("pthread_mutex_init: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}

	static struct option long_options[] = {
		/* long name      | has argument  | flag | short value */
		{ "help",            no_argument,       0, 'h' },
		{ "daemonize",       no_argument,       0, 'd' },
		{ "fs-parent-path",  required_argument, 0, 'f' },
		{ "ta-dir",          required_argument, 0, 't' },
		{ "plugin-path",     required_argument, 0, 'p' },
		{ "rpmb-cid",        required_argument, 0, 'r' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hdf:t:p:r:",
				long_options, &long_index )) != -1) {
		switch (opt) {
			case 'h' :
				return usage(EXIT_SUCCESS);
				break;
			case 'd':
				daemonize = true;
				break;
			case 'f':
				supplicant_params.fs_parent_path = optarg;
				break;
			case 't':
				supplicant_params.ta_dir = optarg;
				break;
			case 'p':
				supplicant_params.plugin_load_path = optarg;
				break;
			case 'r':
				supplicant_params.rpmb_cid = optarg;
				break;
			default:
				return usage(EXIT_FAILURE);
		}
	}

	char filename[15];
    sprintf(filename, "/home/neu/file_%d.txt", gettid());
	FILE *fp = freopen(filename, "a", stdout);

	printf("| %lld | %4d | %d | main()---before if(argv[optind])\n", getMilliseconds(), gettid(), sched_getcpu());

	/* check for non option argument, which is device name */
	if (argv[optind]) {
		
		printf("| %lld | %4d | %d | main()---argv[optind] : %s\n", getMilliseconds(), gettid(), sched_getcpu(), argv[optind]);

		fprintf(stderr, "Using device %s.\n", argv[optind]);
		dev = argv[optind];
		/* check that we do not have too many arguments */
		if (argv[optind + 1]) {
			fprintf(stderr, "Too many arguments passed: extra argument: %s.\n",
					argv[optind+1]);
			return usage(EXIT_FAILURE);
		}
	}


	set_ta_path();

	if (plugin_load_all() != 0) {
		EMSG("failed to load plugins");
		exit(EXIT_FAILURE);
	}

	if (daemonize) {

		printf("| %lld | %4d | %d | main()---daemonize111\n", getMilliseconds(), gettid(), sched_getcpu());

		if (pipe(pipefd) < 0) {
			EMSG("pipe(): %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		e = make_daemon(pipefd);
		if (e < 0) {
			EMSG("make_daemon(): %d", e);
			exit(EXIT_FAILURE);
		}
	}

	if (dev) {

		printf("| %lld | %4d | %d | main()---dev : %s \n", getMilliseconds(), gettid(), sched_getcpu(), dev);

		arg.fd = open_dev(dev, &arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to open \"%s\"", argv[1]);
			exit(EXIT_FAILURE);
		}
	} else {

		printf("| %lld | %4d | %d | main()---dev == NULL\n", getMilliseconds(), gettid(), sched_getcpu());

		arg.fd = get_dev_fd(&arg.gen_caps);
		if (arg.fd < 0) {
			EMSG("failed to find an OP-TEE supplicant device");
			exit(EXIT_FAILURE);
		}
	}

	if (daemonize) {

		printf("| %lld | %4d | %d | main()---daemonize222\n", getMilliseconds(), gettid(), sched_getcpu());

		/* Release parent */
		if (write(pipefd[1], "", 1) != 1) {
			EMSG("write(): %s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		close(pipefd[1]);
	}

	printf("| %lld | %4d | %d | main()---before while\n", getMilliseconds(), gettid(), sched_getcpu());

	while (!arg.abort) {
		if (!process_one_request(&arg)){
			printf("| %lld | %4d | %d | main()---arg.abort == true\n", getMilliseconds(), gettid(), sched_getcpu());
			arg.abort = true;
		}else{
			printf("| %lld | %4d | %d | main()---arg.abort == false\n", getMilliseconds(), gettid(), sched_getcpu());
		}
	}

	close(arg.fd);

	fclose(fp);
	printf("| %lld | %4d | %d | main()---end\n", getMilliseconds(), gettid(), sched_getcpu());

	return EXIT_FAILURE;
}

bool tee_supp_param_is_memref(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		return true;
	default:
		return false;
	}
}

bool tee_supp_param_is_value(struct tee_ioctl_param *param)
{
	switch (param->attr & TEE_IOCTL_PARAM_ATTR_TYPE_MASK) {
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		return true;
	default:
		return false;
	}
}

void *tee_supp_param_to_va(struct tee_ioctl_param *param)
{
	struct tee_shm *tshm = NULL;
	size_t end_offs = 0;

	if (!tee_supp_param_is_memref(param))
		return NULL;

	end_offs = MEMREF_SIZE(param) + MEMREF_SHM_OFFS(param);
	if (end_offs < MEMREF_SIZE(param) || end_offs < MEMREF_SHM_OFFS(param))
		return NULL;

	tshm = find_tshm(MEMREF_SHM_ID(param));
	if (!tshm)
		return NULL;

	if (end_offs > tshm->size)
		return NULL;

	return (uint8_t *)tshm->p + MEMREF_SHM_OFFS(param);
}

void tee_supp_mutex_lock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_lock(mu);

	if (e) {
		EMSG("pthread_mutex_lock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}

void tee_supp_mutex_unlock(pthread_mutex_t *mu)
{
	int e = pthread_mutex_unlock(mu);

	if (e) {
		EMSG("pthread_mutex_unlock: %s", strerror(e));
		EMSG("terminating...");
		exit(EXIT_FAILURE);
	}
}
