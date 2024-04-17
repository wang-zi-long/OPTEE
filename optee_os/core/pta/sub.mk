subdirs-$(CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += tests

srcs-$(CFG_ATTESTATION_PTA) += attestation.c
srcs-$(CFG_TEE_BENCHMARK) += benchmark.c
srcs-$(CFG_DEVICE_ENUM_PTA) += device.c
srcs-$(CFG_TA_GPROF_SUPPORT) += gprof.c
ifeq ($(CFG_WITH_USER_TA),y)
srcs-$(CFG_SECSTOR_TA_MGMT_PTA) += secstor_ta_mgmt.c
endif
srcs-$(CFG_WITH_STATS) += stats.c
srcs-$(CFG_SYSTEM_PTA) += system.c
srcs-$(CFG_SCP03_PTA) += scp03.c
srcs-$(CFG_APDU_PTA) += apdu.c
srcs-$(CFG_SCMI_PTA) += scmi.c
srcs-$(CFG_HWRNG_PTA) += hwrng.c
srcs-$(CFG_RTC_PTA) += rtc.c
srcs-$(CFG_RTC_PTA_HELLO_WORLD) += hello_world_ta.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE) += gprof_rtee.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE1) += gprof_rtee1.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE2) += gprof_rtee2.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE3) += gprof_rtee3.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE4) += gprof_rtee4.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE5) += gprof_rtee5.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE6) += gprof_rtee6.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE7) += gprof_rtee7.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE8) += gprof_rtee8.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE9) += gprof_rtee9.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE10) += gprof_rtee10.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE11) += gprof_rtee11.c
srcs-$(CFG_RTC_PTA_GPROF_RTEE12) += gprof_rtee12.c

subdirs-y += bcm
subdirs-y += tegra
subdirs-y += stm32mp
subdirs-y += imx
subdirs-y += k3
