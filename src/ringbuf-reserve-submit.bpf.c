// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Andrii Nakryiko */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	struct event *e;
	struct event_big *e_big;
	long result;
	const char str1[] = "pushing small event";
	const char str2[] = "pushing BIG event";
	
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	result = bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);
	if (result == sizeof(e->filename))
	{
		// filename was potentially truncated - switch to event_big struct and repeat
		bpf_ringbuf_discard(e, 0);

		e_big = bpf_ringbuf_reserve(&rb, sizeof(*e_big), 0);
		if (!e_big)
			return 0;

		e_big->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(&e_big->comm, sizeof(e_big->comm));
		bpf_probe_read_str(&e_big->filename, sizeof(e_big->filename), (void *)ctx + fname_off);
		e_big->is_big = 1;
		bpf_trace_printk(str2, sizeof(str2));
		bpf_ringbuf_submit(e_big, 0);
	}
	else
	{
		bpf_trace_printk(str1, sizeof(str1));
		e->is_big = 0;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

