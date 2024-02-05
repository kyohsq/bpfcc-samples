import ctypes as ct
from bcc import BPF

bpf = BPF(
    text="""
BPF_RINGBUF_OUTPUT(pid_buf, 8);

int kprobe____x64_sys_execve(void *ctx){
    u32 pid = bpf_get_current_pid_tgid() & 0xffff;
    pid_buf.ringbuf_output(&pid, sizeof(u32), 0);

    return 0;
}
"""
)


def callback(ctx, data, size) -> None:
    pid: ct.c_int = ct.cast(data, ct.POINTER(ct.c_int)).contents
    print(f"hooked (PID: {pid.value})")


bpf["pid_buf"].open_ring_buffer(callback)

while True:
    bpf.ring_buffer_poll()
