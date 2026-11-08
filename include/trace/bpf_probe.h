/* SPDX-License-Identifier: GPL-2.0 */

#undef TRACE_SYSTEM_VAR

#ifdef CONFIG_BPF_EVENTS

/*
 * COUNT_ARGS and CONCATENATE were introduced upstream in 4.17.
 * Provide them here for 4.9 backport compatibility.
 */
#ifndef __CONCAT
#define __CONCAT(a, b)		a ## b
#endif
#ifndef CONCATENATE
#define CONCATENATE(a, b)	__CONCAT(a, b)
#endif

#ifndef __COUNT_ARGS
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, \
		     _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, \
		     _24, _25, _n, X...) _n
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 25, 24, 23, 22, 21, 20, 19, 18, \
				      17, 16, 15, 14, 13, 12, 11, 10, 9, 8, \
				      7, 6, 5, 4, 3, 2, 1, 0)
#endif

#undef __entry
#define __entry entry

#undef __get_dynamic_array
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))

#undef __get_dynamic_array_len
#define __get_dynamic_array_len(field)	\
		((__entry->__data_loc_##field >> 16) & 0xffff)

#undef __get_str
#define __get_str(field) ((char *)__get_dynamic_array(field))

#undef __get_bitmask
#define __get_bitmask(field) (char *)__get_dynamic_array(field)

#undef __perf_count
#define __perf_count(c)	(c)

#undef __perf_task
#define __perf_task(t)	(t)

/*
 * Cast any scalar, pointer, or struct arg to u64 for BPF tracepoint probes.
 * Use a plain u64 destination so this works for structs of any size
 * (the Samsung MSM camera trace events pass structs by value whose sizeof > 8,
 * which caused UINTTYPE to resolve to void and trigger a build error).
 * For args larger than 8 bytes only the low 8 bytes are captured.
 */
#define __CAST_TO_U64(x) ({ \
	u64 __dst = 0; \
	typeof(x) __src = (x); \
	memcpy(&__dst, &__src, \
	       sizeof(__src) <= sizeof(__dst) ? sizeof(__src) : sizeof(__dst)); \
	__dst; })

#define __CAST1(a,...) __CAST_TO_U64(a)
#define __CAST2(a,...) __CAST_TO_U64(a), __CAST1(__VA_ARGS__)
#define __CAST3(a,...) __CAST_TO_U64(a), __CAST2(__VA_ARGS__)
#define __CAST4(a,...) __CAST_TO_U64(a), __CAST3(__VA_ARGS__)
#define __CAST5(a,...) __CAST_TO_U64(a), __CAST4(__VA_ARGS__)
#define __CAST6(a,...) __CAST_TO_U64(a), __CAST5(__VA_ARGS__)
#define __CAST7(a,...) __CAST_TO_U64(a), __CAST6(__VA_ARGS__)
#define __CAST8(a,...) __CAST_TO_U64(a), __CAST7(__VA_ARGS__)
#define __CAST9(a,...) __CAST_TO_U64(a), __CAST8(__VA_ARGS__)
#define __CAST10(a,...) __CAST_TO_U64(a), __CAST9(__VA_ARGS__)
#define __CAST11(a,...) __CAST_TO_U64(a), __CAST10(__VA_ARGS__)
#define __CAST12(a,...) __CAST_TO_U64(a), __CAST11(__VA_ARGS__)
#define __CAST13(a,...) __CAST_TO_U64(a), __CAST12(__VA_ARGS__)
#define __CAST14(a,...) __CAST_TO_U64(a), __CAST13(__VA_ARGS__)
#define __CAST15(a,...) __CAST_TO_U64(a), __CAST14(__VA_ARGS__)
#define __CAST16(a,...) __CAST_TO_U64(a), __CAST15(__VA_ARGS__)
#define __CAST17(a,...) __CAST_TO_U64(a), __CAST16(__VA_ARGS__)
#define __CAST18(a,...) __CAST_TO_U64(a), __CAST17(__VA_ARGS__)
#define __CAST19(a,...) __CAST_TO_U64(a), __CAST18(__VA_ARGS__)
#define __CAST20(a,...) __CAST_TO_U64(a), __CAST19(__VA_ARGS__)
#define __CAST21(a,...) __CAST_TO_U64(a), __CAST20(__VA_ARGS__)
#define __CAST22(a,...) __CAST_TO_U64(a), __CAST21(__VA_ARGS__)
#define __CAST23(a,...) __CAST_TO_U64(a), __CAST22(__VA_ARGS__)
#define __CAST24(a,...) __CAST_TO_U64(a), __CAST23(__VA_ARGS__)
#define __CAST25(a,...) __CAST_TO_U64(a), __CAST24(__VA_ARGS__)
/* tracepoints with more than 25 arguments will hit build error */
#define CAST_TO_U64(...) CONCATENATE(__CAST, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)

#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}

/*
 * This part is compiled out, it is only here as a build time check
 * to make sure that if the tracepoint handling changes, the
 * bpf probe will fail to compile unless it too is updated.
 */
#undef DEFINE_EVENT
#define DEFINE_EVENT(template, call, proto, args)			\
static inline void bpf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(__bpf_trace_##template);	\
}									\
static struct bpf_raw_event_map	__used					\
	__attribute__((section("__bpf_raw_tp_map")))			\
__bpf_trace_tp_map_##call = {						\
	.tp		= &__tracepoint_##call,				\
	.bpf_func	= (void *)__bpf_trace_##template,		\
	.num_args	= COUNT_ARGS(args),				\
};


#undef DEFINE_EVENT_PRINT
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
#endif /* CONFIG_BPF_EVENTS */
