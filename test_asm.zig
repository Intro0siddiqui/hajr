pub fn main() void {
    const key: u32 = 1;
    asm volatile (
        \\movl $0, %%eax
        \\movl $0, %%edx
        \\movl %[k], %%ecx
        \\.byte 0x0f, 0x01, 0xef
        :
        : [k] "r" (key),
        : .{ .eax = true, .ecx = true, .edx = true, .memory = true }
    );
}
