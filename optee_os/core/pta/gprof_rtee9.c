// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <pta_gprof.h>
#include <string.h>

#define TA_RANDOM_UUID_9 \
	{ 0xb6c53aba, 0x9669, 0x4668, \
		{ 0xa7, 0xf2, 0x20, 0x56, 0x29, 0xd0, 0x0f, 0x09} }

TEE_UUID const_uuid_rtee9 = TA_RANDOM_UUID_9;
uint32_t round_cnt_rtee9 = 5;


static TEE_Result gprof_send_rpc_rtee(TEE_UUID *uuid)
{
	struct thread_param params[1] = { };
	struct mobj *mobj;
	TEE_Result res = TEE_ERROR_GENERIC;
	char *va;
	uint32_t iter = 0;

	IMSG("gprof_rtee_9---gprof_send_rpc_rtee!!!\n");

	mobj = thread_rpc_alloc_payload(sizeof(*uuid));
	
	if (!mobj){
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee( !!!mobj )\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}else{
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee( mobj )\n");
	}

	va = mobj_get_va(mobj, 0, sizeof(*uuid));
	if (!va){
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee( !!!va )\n");
		goto exit;
	}else{
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee( va )\n");
	}

	memcpy(va, uuid, sizeof(*uuid));

	params[0] = THREAD_PARAM_VALUE(INOUT, 3535, 0, 0);

	IMSG("gprof_rtee_9---gprof_send_rpc_rtee( before for )\n");

	for (iter = 0; iter < round_cnt_rtee9; iter++){
		res = thread_rpc_cmd(OPTEE_RPC_CMD_GPROF, 1, params);
		if (res != TEE_SUCCESS){
			IMSG("gprof_rtee_9---gprof_send_rpc_rtee( not TEE_SUCCESS )\n");
		}else{
			IMSG("gprof_rtee_9---gprof_send_rpc_rtee( TEE_SUCCESS )\n");
		}
	}

	if (res != TEE_SUCCESS)
		goto exit;

exit:
	thread_rpc_free_payload(mobj);
	return res;
}

static TEE_Result gprof_send(struct ts_session *s, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	IMSG("gprof_rtee_9---gprof_send!!!\n");

	(void) s;

	TEE_Result res = gprof_send_rpc_rtee(&const_uuid_rtee9);

	if(res == TEE_SUCCESS){
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee success!!!\n");
	}else{
		IMSG("gprof_rtee_9---gprof_send_rpc_rtee not success!!!\n");
	}


	return 0;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	IMSG("gprof_rtee_9---open_session!!!\n");

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct ts_session *s = ts_get_calling_session();

	IMSG("gprof_rtee_9---invoke_command!!!\n");
	
	switch (cmd_id) {
	case PTA_GPROF_SEND:
		return gprof_send(s, param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = TA_RANDOM_UUID_9, .name = "gprof_rtee_9",
			.flags = PTA_DEFAULT_FLAGS,
			.open_session_entry_point = open_session,
			.invoke_command_entry_point = invoke_command);
