from bcc import BPF

IF = "enp0s3"

bpf = BPF(
    text="""
#include <uapi/linux/bpf.h>  // for xdp_md

int show_first_byte(struct xdp_md *ctx){
    u8 *from = (u8 *)(u64)ctx->data;
    u8 *to = (u8 *)(u64)ctx->data_end;

    // This line is required to pass BPF verifier
    if(from + 1 > to)
        return XDP_DROP;

    bpf_trace_printk("first byte: 0x%x", from[0] & 0xFF);

    return XDP_PASS;  // NOTE: do not return 0; frame will be droped
}
"""
)

func = bpf.load_func("show_first_byte", BPF.XDP)
bpf.attach_xdp(IF, func, 0)

try:
    bpf.trace_print()
except KeyboardInterrupt:
    pass

# NOTE: do not forget detaching the func
bpf.remove_xdp(IF, 0)
