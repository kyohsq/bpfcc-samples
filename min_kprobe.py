from bcc import BPF

BPF(
    text="""
int kprobe____x64_sys_execve(void *ctx){
    bpf_trace_printk("hi");
    return 0;
}
"""
).trace_print()
