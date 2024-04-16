/*
 * Copyright (c) 2016, Linaro Limited
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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

#define PTA_INVOKE_TESTS_UUID \
		{ 0xd96a5b40, 0xc3e5, 0x21e3, \
			{0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b} }

#define STATS_UUID \
		{ 0xd96a5b40, 0xe2c7, 0xb1af, \
			{0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b} }

#define PTA_SYSTEM_UUID \
		{ 0x3a2f8978, 0x5dc0, 0x11e8, \
			{0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc} }

#define BENCHMARK_UUID \
		{ 0x0b9a63b0, 0xb4c6, 0x4c85, \
			{0xa2, 0x84, 0xa2, 0x28, 0xef, 0x54, 0x7b, 0x4e} }

#define PTA_ATTESTATION_UUID \
		{ 0x39800861, 0x182a, 0x4720, \
			{0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5} }

#define TA_RANDOM_UUID \
		{ 0xb6c53aba, 0x9669, 0x4668, \
			{ 0xa7, 0xf2, 0x20, 0x56, 0x29, 0xd0, 0x0f, 0x86} }

#define BENCHMARK_CMD(id)	(0xFA190000 | ((id) & 0xFFFF))
#define BENCHMARK_CMD_REGISTER_MEMREF	BENCHMARK_CMD(1)
#define BENCHMARK_CMD_GET_MEMREF		BENCHMARK_CMD(2)
#define BENCHMARK_CMD_UNREGISTER		BENCHMARK_CMD(3)

void* function1(void *arg){

	TEEC_Context bench_ctx;
	TEEC_Session bench_sess;

	TEEC_Result res = TA_RANDOM_UUID;
	uint32_t ret_orig = 0;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));

	res = TEEC_InitializeContext(NULL, &bench_ctx);

	TEEC_UUID pta_benchmark_uuid = BENCHMARK_UUID;

	res = TEEC_OpenSession(&bench_ctx, &bench_sess,
			&pta_benchmark_uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);
	
	if (res != TEEC_SUCCESS){
		printf("TEEC_OpenSession error!!!\n");
	}else{
		printf("TEEC_OpenSession success!!!\n");
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = 10;
	op.params[0].value.b = 0;

	res = TEEC_InvokeCommand(&bench_sess, 0,
					&op, &ret_orig);

	if (res != TEEC_SUCCESS){
		printf("TEEC_InvokeCommand error!!!\n");
	}else{
		printf("TEEC_InvokeCommand success!!!\n");
	}

	TEEC_CloseSession(&bench_sess);
	TEEC_FinalizeContext(&bench_ctx);

	return NULL;
}

int main(void)
{	
	pthread_t thread1;
	int thread1_arg = 1;
	pthread_create(&thread1, NULL, function1, (void*)&thread1_arg);
	pthread_join(thread1, NULL);
	return 0;
}
