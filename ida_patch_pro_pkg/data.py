"""Static hint/reference data for ida_patch_pro."""

import re

MNEMONIC_HINTS = {
    "mov": "数据传送指令。常用于寄存器赋值、立即数加载、参数准备。",
    "lea": "加载有效地址。常用于取指针、做地址计算，不会真正访问内存。",
    "push": "压栈。常用于保存现场、传参或构造栈帧。",
    "pop": "出栈。常用于恢复寄存器或回收参数。",
    "call": "函数调用。会保存返回地址，并跳转到目标函数。",
    "jmp": "无条件跳转。直接改变控制流，不返回。",
    "jz": "零标志为 1 时跳转，常见于比较结果为相等。",
    "je": "等于时跳转，本质上与 jz 类似。",
    "jnz": "零标志为 0 时跳转，常见于比较结果不相等。",
    "jne": "不等于时跳转，本质上与 jnz 类似。",
    "jg": "大于时跳转。常见于有符号比较后，条件为 ZF=0 且 SF=OF。",
    "jle": "小于等于时跳转。常见于有符号比较后，条件为 ZF=1 或 SF!=OF。",
    "cmp": "比较两个操作数，只更新标志位，不保存结果。",
    "test": "按位测试，只更新标志位，常用于判断是否为 0。",
    "xor": "按位异或。`xor reg, reg` 常用于高效清零。",
    "and": "按位与。常用于掩码处理和位清理。",
    "or": "按位或。常用于置位或合并标志。",
    "add": "加法运算，并更新标志位。",
    "sub": "减法运算，并更新标志位。",
    "inc": "自增 1。常用于循环计数或简单加一。",
    "dec": "自减 1。常用于循环计数或简单减一。",
    "shl": "逻辑左移。常用于乘 2 的幂或构造位字段。",
    "shr": "逻辑右移。常用于无符号除 2 的幂或取高位。",
    "sar": "算术右移。常用于带符号除 2 的幂并保留符号。",
    "sal": "算术左移，通常与 shl 等价。",
    "not": "按位取反。",
    "neg": "取相反数，等价于 0 减去该操作数。",
    "movzx": "零扩展传送。把较小操作数无符号扩展后写入目标。",
    "movsx": "符号扩展传送。把较小操作数按有符号值扩展后写入目标。",
    "setz": "条件置位指令。若条件满足则把目标字节写成 1，否则写成 0。`setz` 对应 ZF=1。",
    "movaps": "对齐的 128 位向量搬运。源/目标通常是 XMM 寄存器或对齐的 16 字节内存。",
    "movups": "非对齐的 128 位向量搬运。源/目标通常是 XMM 寄存器或内存。",
    "movdqa": "对齐的整数向量搬运。常用于 XMM 寄存器和 16 字节内存之间。",
    "movdqu": "非对齐的整数向量搬运。",
    "pxor": "SIMD 按位异或。`pxor xmm0, xmm0` 常用于清零 XMM 寄存器。",
    "xorps": "浮点/SIMD 按位异或。`xorps xmm0, xmm0` 也常用于清零 XMM 寄存器。",
    "stosb": "把 `AL` 写到 `RDI/EDI` 指向的位置，并按方向标志调整指针。常见于字符串/内存填充代码。",
    "stosd": "把 `EAX` 写到目标位置，并按元素大小推进指针。常见于批量初始化。",
    "stosq": "把 `RAX` 写到目标位置，并按 8 字节推进指针。常见于 64 位内存填充。",
    "rep stosb": "重复执行 `stosb`，次数通常由 `RCX/ECX` 控制。常见于 `memset` 风格填充。",
    "rep stosd": "重复执行 `stosd`，常见于按双字批量填充内存。",
    "rep stosq": "重复执行 `stosq`，常见于 64 位环境下的大块内存清零或填充。",
    "movsb": "把 `[RSI/ESI]` 的字节拷贝到 `[RDI/EDI]`，并自动推进源/目标指针。",
    "movsq": "按 8 字节搬运字符串元素，常见于批量拷贝。",
    "rep movsb": "重复执行 `movsb`，次数通常由 `RCX/ECX` 控制。常见于 `memcpy/memmove` 风格代码。",
    "rep movsq": "重复执行 `movsq`，常见于 64 位批量内存复制。",
    "scasb": "把 `AL` 与目标内存比较，并推进扫描指针。常见于字符串搜索。",
    "repne scasb": "反复扫描字节直到匹配或计数耗尽。常见于字符串长度/搜索逻辑。",
    "lodsb": "把源地址的字节装入 `AL` 并推进源指针。常见于字符串遍历。",
    "int3": "软件断点指令。常用于调试、补丁占位或故意中断执行。",
    "ud2": "无条件非法指令。执行时会触发异常，常用于不可达路径、崩溃保护或反调试场景。",
    "hlt": "停止处理器执行，直到外部中断或异常到来。用户态执行通常会触发异常，常见于保护、陷阱或占位场景。",
    "align": "伪指令。用于把当前位置对齐到指定边界，汇编器会自动填充 NOP 或等价字节。",
    "syscall": "进入系统调用。x86/x64 下常用于从用户态切入内核服务，Linux 常配合 `rax/rdi/rsi/rdx/r10/r8/r9` 传参。",
    "cmovnb": "条件移动指令。仅当条件满足时才移动源操作数到目标。`cmovnb` 对应 CF=0。",
    "xchg": "交换两个操作数。",
    "leave": "销毁当前栈帧，常见于函数尾部。",
    "imul": "有符号乘法。",
    "mul": "无符号乘法。",
    "div": "无符号除法，通常配合特定寄存器使用。",
    "idiv": "有符号除法，通常配合特定寄存器使用。",
    "ret": "函数返回。通常从栈上取回返回地址。",
    "nop": "空操作。常用于补齐长度、对齐或屏蔽逻辑。",
    "cbz": "寄存器为 0 时跳转，常见于 ARM/AArch64。",
    "cbnz": "寄存器非 0 时跳转，常见于 ARM/AArch64。",
}

# 寄存器说明表：用于解释寄存器在常见 ABI/场景下的典型用途。
REGISTER_HINTS = {
    "rax": "累加器寄存器。常用于函数返回值、算术运算。",
    "eax": "RAX 的低 32 位。写入时会清零高 32 位。",
    "ax": "RAX 的低 16 位。常见于较老代码、端口/短整数操作。",
    "ah": "RAX 的位 8-15。老式 8 位操作中常见。",
    "al": "RAX 的低 8 位，常用于返回值、字符或字节处理。",
    "rbx": "通用寄存器。常作为被调用者保存寄存器。",
    "ebx": "RBX 的低 32 位。",
    "bx": "RBX 的低 16 位。",
    "bh": "RBX 的位 8-15。",
    "bl": "RBX 的低 8 位。",
    "rcx": "常用于第 1 个整数参数（Windows x64），也常作计数器。",
    "ecx": "RCX 的低 32 位。",
    "cx": "RCX 的低 16 位。",
    "ch": "RCX 的位 8-15。",
    "cl": "RCX 的低 8 位，移位指令里常见。",
    "rdx": "常用于第 2 个整数参数（Windows x64）。",
    "edx": "RDX 的低 32 位。",
    "dx": "RDX 的低 16 位。",
    "dh": "RDX 的位 8-15。",
    "dl": "RDX 的低 8 位。",
    "r8": "常用于第 3 个整数参数（Windows x64）。",
    "r8d": "R8 的低 32 位。",
    "r9": "常用于第 4 个整数参数（Windows x64）。",
    "r9d": "R9 的低 32 位。",
    "r10": "通用临时寄存器，常用于中转或 syscall 相关约定。",
    "r11": "通用临时寄存器，常被调用者自由破坏。",
    "r12": "常作为被调用者保存寄存器。",
    "r13": "常作为被调用者保存寄存器。",
    "r14": "常作为被调用者保存寄存器。",
    "r15": "常作为被调用者保存寄存器。",
    "rsi": "源寄存器。字符串操作或函数参数中常见。",
    "esi": "RSI 的低 32 位。",
    "si": "RSI 的低 16 位。",
    "sil": "RSI 的低 8 位。",
    "rdi": "目标寄存器。Windows x64 下常作普通寄存器；某些库/编译器场景里常作缓冲区指针。",
    "edi": "RDI 的低 32 位。写入时会清零高 32 位。",
    "di": "RDI 的低 16 位。",
    "dil": "RDI 的低 8 位。",
    "rbp": "栈帧基址寄存器，常用于访问局部变量。",
    "ebp": "RBP 的低 32 位。",
    "bp": "RBP 的低 16 位。",
    "bpl": "RBP 的低 8 位。",
    "rsp": "栈顶指针，函数调用和局部变量分配核心寄存器。",
    "esp": "RSP 的低 32 位。",
    "sp": "栈指针。",
    "spl": "RSP 的低 8 位。",
    "rip": "指令指针，指向当前执行位置。",
    "eip": "32 位指令指针。",
    "ip": "16 位指令指针。",
    "rflags": "64 位标志寄存器。保存 CF/ZF/SF/OF 等状态位。",
    "eflags": "32 位标志寄存器。",
    "flags": "标志寄存器统称。",
    "xmm0": "SIMD 寄存器。浮点返回值、向量运算中常见。",
    "xmm1": "SIMD 寄存器。",
    "xmm2": "SIMD 寄存器。",
    "xmm3": "SIMD 寄存器。",
    "x0": "AArch64 第 1 个参数/返回值寄存器。",
    "x1": "AArch64 第 2 个参数寄存器。",
    "x2": "AArch64 第 3 个参数寄存器。",
    "x3": "AArch64 第 4 个参数寄存器。",
    "x29": "AArch64 帧指针。",
    "x30": "AArch64 链接寄存器，保存返回地址。",
    "sp": "栈指针。",
    "lr": "链接寄存器，常用于返回地址。",
    "pc": "程序计数器。",
    "$sp": "MIPS 栈指针。",
    "$ra": "MIPS 返回地址寄存器。",
    "$a0": "MIPS 第 1 个参数寄存器。",
    "$a1": "MIPS 第 2 个参数寄存器。",
    "$a2": "MIPS 第 3 个参数寄存器。",
    "$a3": "MIPS 第 4 个参数寄存器。",
    "$v0": "MIPS 返回值寄存器。",
}


def _register_hint(reg, arch_key):
    """Return a human-friendly description for the given register name."""
    reg = reg.lower()
    if reg in REGISTER_HINTS:
        return REGISTER_HINTS[reg]

    if arch_key == "x86/x64":
        m = re.fullmatch(r"r(1[0-5]|[8-9])", reg)
        if m:
            idx = m.group(1)
            return "通用 64 位寄存器 r%s。x64 下常作临时寄存器；r12-r15 通常偏向被调用者保存。" % idx
        m = re.fullmatch(r"r(1[0-5]|[8-9])d", reg)
        if m:
            return "对应 64 位寄存器的低 32 位。写入时会清零高 32 位。"
        m = re.fullmatch(r"r(1[0-5]|[8-9])w", reg)
        if m:
            return "对应 64 位寄存器的低 16 位。"
        m = re.fullmatch(r"r(1[0-5]|[8-9])b", reg)
        if m:
            return "对应 64 位寄存器的低 8 位。"
        m = re.fullmatch(r"(xmm|ymm|zmm)([0-9]|1[0-5])", reg)
        if m:
            kind = m.group(1).upper()
            return "%s 向量寄存器。用于 SSE/AVX/AVX-512 浮点和 SIMD 运算。" % kind
        m = re.fullmatch(r"st\(?([0-7])\)?", reg)
        if m:
            return "x87 FPU 栈寄存器 ST(%s)。用于老式浮点计算。" % m.group(1)

    if arch_key == "ARM/Thumb":
        arm_map = {
            "r0": "ARM 第 1 个参数寄存器，也常用于返回值。",
            "r1": "ARM 第 2 个参数寄存器。",
            "r2": "ARM 第 3 个参数寄存器。",
            "r3": "ARM 第 4 个参数寄存器。",
            "r4": "常见的被调用者保存寄存器。",
            "r5": "常见的被调用者保存寄存器。",
            "r6": "常见的被调用者保存寄存器。",
            "r7": "常见的被调用者保存寄存器；某些环境下也会作帧指针。",
            "r8": "常见的被调用者保存寄存器。",
            "r9": "平台相关寄存器，可能用于静态基址或通用保存。",
            "r10": "常见的被调用者保存寄存器。",
            "r11": "常作为帧指针 FP。",
            "r12": "IP/Intra-procedure-call scratch，常作临时寄存器。",
            "r13": "SP，栈指针。",
            "r14": "LR，链接寄存器，通常保存返回地址。",
            "r15": "PC，程序计数器。",
            "sp": "ARM 栈指针。",
            "lr": "ARM 链接寄存器，通常保存返回地址。",
            "pc": "ARM 程序计数器。",
            "fp": "ARM 帧指针，常对应 r11。",
            "ip": "ARM 临时寄存器，常对应 r12。",
        }
        return arm_map.get(reg)

    if arch_key == "AArch64":
        if reg in ("sp", "wsp"):
            return "AArch64 栈指针。"
        if reg in ("fp", "x29"):
            return "AArch64 帧指针。"
        if reg in ("lr", "x30"):
            return "AArch64 链接寄存器，通常保存返回地址。"
        m = re.fullmatch(r"x([0-9]|[12][0-9]|30)", reg)
        if m:
            idx = int(m.group(1))
            if idx == 0:
                return "AArch64 第 1 个参数寄存器，也常用于返回值。"
            if idx == 1:
                return "AArch64 第 2 个参数寄存器。"
            if idx == 2:
                return "AArch64 第 3 个参数寄存器。"
            if idx == 3:
                return "AArch64 第 4 个参数寄存器。"
            if 4 <= idx <= 7:
                return "AArch64 参数寄存器 x%d。" % idx
            if idx == 8:
                return "AArch64 间接返回值地址/系统调用号等场景的特殊寄存器，也常作临时寄存器。"
            if 9 <= idx <= 15:
                return "AArch64 临时寄存器 x%d。" % idx
            if 19 <= idx <= 28:
                return "AArch64 被调用者保存寄存器 x%d。" % idx
            return "AArch64 通用 64 位寄存器 x%d。" % idx
        m = re.fullmatch(r"w([0-9]|[12][0-9]|30)", reg)
        if m:
            return "对应 X 寄存器的低 32 位视图。写入时会清零高 32 位。"
        m = re.fullmatch(r"v([0-9]|[12][0-9]|3[01])", reg)
        if m:
            return "AArch64 SIMD/浮点寄存器 V%s。" % m.group(1)

    if arch_key == "MIPS":
        mips_map = {
            "$zero": "常量 0 寄存器，始终读为 0。",
            "$at": "汇编器临时寄存器。",
            "$v0": "返回值寄存器，也常用于系统调用号。",
            "$v1": "辅助返回值寄存器。",
            "$a0": "第 1 个参数寄存器。",
            "$a1": "第 2 个参数寄存器。",
            "$a2": "第 3 个参数寄存器。",
            "$a3": "第 4 个参数寄存器。",
            "$gp": "全局指针寄存器。",
            "$sp": "栈指针。",
            "$fp": "帧指针。",
            "$ra": "返回地址寄存器。",
            "$k0": "内核保留寄存器。",
            "$k1": "内核保留寄存器。",
        }
        if reg in mips_map:
            return mips_map[reg]
        m = re.fullmatch(r"\$t([0-9])", reg)
        if m:
            return "MIPS 临时寄存器 $t%s，通常由调用者保存。" % m.group(1)
        m = re.fullmatch(r"\$s([0-7])", reg)
        if m:
            return "MIPS 保存寄存器 $s%s，通常由被调用者保存。" % m.group(1)

    return None

ARCH_SYNTAX_HELP = {
    "x86/x64": {
        "note": "x86/x64 指令长度可变，下面的字节长度和十六进制是常见写法的典型值，实际结果会随操作数和寻址方式变化。",
        "rows": [
            ("mov eax, ebx", "mov dst, src", "89 D8", "2 bytes", "寄存器/内存之间传送数据"),
            ("push ebp", "push src", "55", "1 byte", "压栈，常用于保存寄存器或传参"),
            ("pop ebp", "pop dst", "5D", "1 byte", "出栈到目标操作数"),
            ("lea eax, [ebx+4]", "lea dst, [addr]", "8D 43 04", "3-7 bytes", "取有效地址，不访问内存"),
            ("add eax, 1", "add dst, src", "83 C0 01", "3-6 bytes", "加法运算并更新标志位"),
            ("sub eax, 1", "sub dst, src", "83 E8 01", "3-6 bytes", "减法运算并更新标志位"),
            ("inc eax", "inc dst", "FF C0", "2 bytes", "自增 1"),
            ("dec eax", "dec dst", "FF C8", "2 bytes", "自减 1"),
            ("xor eax, eax", "xor dst, src", "31 C0", "2 bytes", "异或，常用于清零寄存器"),
            ("and eax, 0FFh", "and dst, src", "25 FF 00 00 00", "5 bytes", "按位与，常用于掩码"),
            ("or eax, 1", "or dst, src", "83 C8 01", "3-6 bytes", "按位或，常用于置位"),
            ("shl eax, 1", "shl dst, count", "D1 E0", "2 bytes", "逻辑左移"),
            ("shr eax, 1", "shr dst, count", "D1 E8", "2 bytes", "逻辑右移"),
            ("sar eax, 1", "sar dst, count", "D1 F8", "2 bytes", "算术右移"),
            ("sar eax, cl", "sar dst, cl", "D3 F8", "2 bytes", "按 `cl` 指定的位数做算术右移"),
            ("cmp eax, ebx", "cmp left, right", "39 D8", "2-6 bytes", "比较两个操作数，只更新标志位"),
            ("test eax, eax", "test left, right", "85 C0", "2 bytes", "按位与测试，不保存结果"),
            ("movzx eax, byte ptr [rbx]", "movzx dst, src", "0F B6 03", "3+ bytes", "无符号扩展读取"),
            ("movzx edx, byte ptr [rdi]", "movzx dst, src", "0F B6 17", "3 bytes", "把 8 位无符号值扩展到 32 位"),
            ("movsx eax, byte ptr [rbx]", "movsx dst, src", "0F BE 03", "3+ bytes", "有符号扩展读取"),
            ("setz dl", "setcc r/m8", "0F 94 C2", "3 bytes", "条件满足时把目标字节置为 1，否则置为 0"),
            ("cmovnb rbp, r13", "cmovcc dst, src", "49 0F 43 ED", "4 bytes", "仅当条件满足时才移动，`cmovnb` 对应 CF=0"),
            ("xchg eax, ebx", "xchg left, right", "93", "1 byte", "交换两个寄存器"),
            ("stosb", "stosb", "AA", "1 byte", "把 AL 写到 [RDI/EDI] 并推进指针"),
            ("stosq", "stosq", "48 AB", "2 bytes", "把 RAX 写到 [RDI] 并推进 8 字节"),
            ("rep stosq", "rep stosq", "F3 48 AB", "3 bytes", "重复执行 stosq，常见于 memset/清零"),
            ("movsb", "movsb", "A4", "1 byte", "从 [RSI] 复制 1 字节到 [RDI]"),
            ("rep movsb", "rep movsb", "F3 A4", "2 bytes", "重复执行 movsb，常见于 memcpy/memmove"),
            ("scasb", "scasb", "AE", "1 byte", "用 AL 扫描目标字节"),
            ("repne scasb", "repne scasb", "F2 AE", "2 bytes", "重复扫描直到命中或计数耗尽"),
            ("lodsb", "lodsb", "AC", "1 byte", "把 [RSI] 的字节装入 AL"),
            ("int3", "int3", "CC", "1 byte", "软件断点"),
            ("ud2", "ud2", "0F 0B", "2 bytes", "显式触发非法指令异常"),
            ("hlt", "hlt", "F4", "1 byte", "停止处理器执行，常见于陷阱或保护代码"),
            ("align 10h", "align boundary", "66 90 / 90...", "1+ bytes", "把当前位置补齐到目标边界，常由 NOP 序列实现"),
            ("syscall", "syscall", "0F 05", "2 bytes", "进入系统调用"),
            ("call 401000h", "call target", "E8 xx xx xx xx", "5 bytes", "调用函数或子过程"),
            ("jmp short loc_401020", "jmp target", "EB xx / E9 xx xx xx xx", "2 or 5 bytes", "无条件跳转"),
            ("jz short loc_401030", "jcc target", "74 xx / 0F 84 xx xx xx xx", "2 or 6 bytes", "条件跳转，依赖标志位"),
            ("jg loc_4050E0", "jcc target", "0F 8F xx xx xx xx", "6 bytes", "大于时跳转，常用于有符号比较"),
            ("jle loc_404FC5", "jcc target", "0F 8E xx xx xx xx", "6 bytes", "小于等于时跳转，常用于有符号比较"),
            ("nop", "nop", "90", "1 byte", "空操作，用于填充或屏蔽指令"),
            ("leave", "leave", "C9", "1 byte", "销毁当前栈帧"),
            ("ret", "ret", "C3", "1 byte", "函数返回"),
        ],
    },
    "ARM/Thumb": {
        "note": "ARM32 大多数 ARM 指令为 4 字节；Thumb 指令常见为 2 字节，也可能是 4 字节。十六进制按小端序展示。",
        "rows": [
            ("MOV R0, R1", "MOV Rd, Rm/#imm", "ARM: 01 00 A0 E1 / Thumb: 08 46", "ARM: 4 / Thumb: 2-4", "寄存器赋值"),
            ("LDR R0, [R1,#4]", "LDR Rt, [Rn,#imm]", "ARM: 04 00 91 E5 / Thumb: 48 68", "ARM: 4 / Thumb: 2-4", "从内存加载数据"),
            ("STR R0, [R1,#4]", "STR Rt, [Rn,#imm]", "ARM: 04 00 81 E5 / Thumb: 48 60", "ARM: 4 / Thumb: 2-4", "把数据写入内存"),
            ("ADD R0, R0, #1", "ADD Rd, Rn, op2", "ARM: 01 00 80 E2 / Thumb: 40 1C", "ARM: 4 / Thumb: 2-4", "加法运算"),
            ("SUB R0, R0, #1", "SUB Rd, Rn, op2", "ARM: 01 00 40 E2 / Thumb: 40 1E", "ARM: 4 / Thumb: 2-4", "减法运算"),
            ("CMP R0, #0", "CMP Rn, op2", "ARM: 00 00 50 E3 / Thumb: 00 28", "ARM: 4 / Thumb: 2", "比较并更新标志位"),
            ("BL sub_1000", "BL target", "ARM: xx xx xx EB / Thumb: xx F0 xx F8", "ARM: 4 / Thumb: 4", "带返回地址的调用"),
            ("B loc_2000", "B target", "ARM: xx xx xx EA / Thumb: xx E0", "ARM: 4 / Thumb: 2-4", "无条件跳转"),
            ("BEQ loc_2000", "B<cond> target", "ARM: xx xx xx 0A / Thumb: xx D0", "ARM: 4 / Thumb: 2-4", "条件跳转"),
            ("CBZ R0, loc_2000", "CBZ Rt, target", "Thumb: xx B1", "Thumb: 2-4", "寄存器为 0 时跳转"),
            ("NOP", "NOP", "ARM: 00 00 A0 E1 / Thumb: 00 BF", "ARM: 4 / Thumb: 2", "空操作"),
            ("BX LR", "BX Rm", "1E FF 2F E1", "4 bytes", "跳转到寄存器，常用于返回"),
        ],
    },
    "AArch64": {
        "note": "AArch64 指令定长，绝大多数都是 4 字节。十六进制按小端序展示。",
        "rows": [
            ("MOV X0, X1", "MOV Xd/Wd, Xn/Wn/#imm", "E0 03 01 AA", "4 bytes", "寄存器或立即数赋值"),
            ("LDR X0, [X1,#8]", "LDR Xt, [Xn,#imm]", "20 04 40 F9", "4 bytes", "从内存加载数据"),
            ("STR X0, [X1,#8]", "STR Xt, [Xn,#imm]", "20 04 00 F9", "4 bytes", "写内存"),
            ("ADD X0, X0, #1", "ADD Xd, Xn, #imm", "00 04 00 91", "4 bytes", "加法运算"),
            ("SUB X0, X0, #1", "SUB Xd, Xn, #imm", "00 04 00 D1", "4 bytes", "减法运算"),
            ("CMP X0, #0", "CMP Xn, #imm/reg", "1F 00 00 F1", "4 bytes", "比较并设置标志位"),
            ("BL sub_1000", "BL target", "xx xx xx 94", "4 bytes", "函数调用"),
            ("B loc_2000", "B target", "xx xx xx 14", "4 bytes", "无条件跳转"),
            ("B.EQ loc_2000", "B.<cond> target", "xx xx xx 54", "4 bytes", "条件跳转"),
            ("CBZ X0, loc_2000", "CBZ Xt, target", "xx xx xx B4", "4 bytes", "寄存器为 0 时跳转"),
            ("CBNZ X0, loc_2000", "CBNZ Xt, target", "xx xx xx B5", "4 bytes", "寄存器非 0 时跳转"),
            ("ADRP X0, sym", "ADRP Xd, sym", "xx xx xx 90", "4 bytes", "装载页基址，常见于位置无关代码"),
            ("NOP", "NOP", "1F 20 03 D5", "4 bytes", "空操作"),
            ("RET", "RET [Xn]", "C0 03 5F D6", "4 bytes", "函数返回"),
        ],
    },
    "MIPS": {
        "note": "MIPS 常见指令基本都是定长 4 字节。十六进制按常见小端展示，伪指令可能展开成多条真实指令。",
        "rows": [
            ("move $t0, $t1", "move rd, rs", "25 40 20 01", "4 bytes", "寄存器复制，通常是伪指令"),
            ("li $t0, 1", "li rt, imm", "01 00 08 24", "4-8 bytes", "加载立即数，常为伪指令"),
            ("lw $t0, 4($sp)", "lw rt, off(base)", "04 00 A8 8F", "4 bytes", "从内存读取字"),
            ("sw $t0, 4($sp)", "sw rt, off(base)", "04 00 A8 AF", "4 bytes", "向内存写字"),
            ("addiu $sp, $sp, -0x20", "addiu rt, rs, imm", "E0 FF BD 27", "4 bytes", "带立即数加法"),
            ("lui $t0, 1234h", "lui rt, imm", "34 12 08 3C", "4 bytes", "加载高 16 位立即数"),
            ("beq $t0, $zero, loc_1000", "beq rs, rt, target", "xx xx 00 11", "4 bytes", "条件相等跳转"),
            ("bnez $t0, loc_2000", "bnez rs, target", "xx xx 00 15", "4 bytes", "条件不等于 0 跳转"),
            ("b loc_2000", "b target", "xx xx xx 10", "4 bytes", "无条件跳转，常为伪指令"),
            ("jal sub_3000", "jal target", "xx xx xx 0C", "4 bytes", "函数调用"),
            ("jr $ra", "jr rs", "08 00 E0 03", "4 bytes", "跳转寄存器，常用于返回"),
            ("nop", "nop", "00 00 00 00", "4 bytes", "空操作"),
        ],
    },
}


# 按架构整理的寄存器速查表：用于单独的寄存器帮助窗口。
ARCH_REGISTER_HELP = {
    "x86/x64": {
        "note": "x86/x64 这里按常见逆向和补丁场景整理。参数/返回值说明默认更偏 Windows x64 习惯用法。",
        "rows": [
            ("rax / eax / ax / al", "累加器", "返回值、算术、临时值", "写 `eax` 会自动清零 `rax` 高 32 位"),
            ("rbx / ebx / bx / bl", "保存寄存器", "通用保存、对象上下文", "常见被调用者保存寄存器"),
            ("rcx / ecx / cx / cl", "参数/计数器", "第 1 整数参数、循环计数", "`cl` 常作移位次数"),
            ("rdx / edx / dx / dl", "参数", "第 2 整数参数、乘除法辅助", "除法场景常与 `rax` 联动"),
            ("r8 / r8d / r8w / r8b", "参数", "第 3 整数参数", "Windows x64 常见"),
            ("r9 / r9d / r9w / r9b", "参数", "第 4 整数参数", "Windows x64 常见"),
            ("r10 / r10d / r10w / r10b", "临时寄存器", "中转、跳板、syscall 相关", "通常由调用者保存"),
            ("r11 / r11d / r11w / r11b", "临时寄存器", "短期临时值", "常被自由破坏"),
            ("r12-r15", "保存寄存器", "长期保存数据、对象指针", "通常偏向被调用者保存"),
            ("rsi / esi / si / sil", "源寄存器", "字符串操作、地址中转", "不同 ABI 下也可能作参数寄存器"),
            ("rdi / edi / di / dil", "目标寄存器", "字符串操作、缓冲区指针、临时值", "逆向里常见目的地址/对象地址"),
            ("rbp / ebp / bp / bpl", "帧指针", "访问局部变量、维持栈框架", "开启优化后也可能退化成普通寄存器"),
            ("rsp / esp / sp / spl", "栈指针", "调用、返回、局部变量分配", "修改前必须确认栈平衡"),
            ("rip / eip / ip", "指令指针", "当前执行位置", "通常通过跳转/调用间接改变"),
            ("rflags / eflags", "标志寄存器", "ZF/CF/SF/OF 等条件状态", "`cmp/test/add/sub` 等会更新它"),
            ("xmm0-xmm3", "SIMD/参数/返回值", "浮点返回值、向量计算、前几个 SIMD 参数", "`xmm0` 常见于返回值"),
            ("xmm4-xmm15", "SIMD 寄存器", "向量/浮点临时值", "逆向 SSE/AVX 代码时常见"),
            ("ymm0-ymm15", "AVX 寄存器", "256 位向量运算", "与 `xmm` 为同一寄存器的更宽视图"),
            ("zmm0-zmm31", "AVX-512 寄存器", "512 位向量运算", "需要目标环境支持 AVX-512"),
            ("st(0)-st(7)", "x87 FPU 栈", "老式浮点计算", "现代编译器里已较少"),
        ],
    },
    "ARM/Thumb": {
        "note": "ARM/Thumb 这里按经典 ARM32 调用习惯整理，便于看参数、返回值和栈相关寄存器。",
        "rows": [
            ("r0-r3", "参数/返回值", "前 4 个参数，`r0` 常见返回值", "最常见的参数寄存器组"),
            ("r4-r7", "保存寄存器", "长期保存局部值、对象指针", "通常由被调用者保存"),
            ("r8-r11", "保存寄存器/帧相关", "局部状态、帧指针", "`r11` 常见作 `fp`"),
            ("r12 / ip", "临时寄存器", "过程内临时值、中转", "常见 scratch register"),
            ("r13 / sp", "栈指针", "函数栈顶、局部变量分配", "修改前需确认栈平衡"),
            ("r14 / lr", "链接寄存器", "保存返回地址", "调用后通常写入返回位置"),
            ("r15 / pc", "程序计数器", "当前执行位置", "常通过分支/返回改变"),
            ("fp", "帧指针别名", "常对应 `r11`", "便于读函数栈框架"),
            ("s0-s31", "VFP 标量寄存器", "浮点运算", "单精度视图"),
            ("d0-d31", "VFP 双精度寄存器", "浮点/NEON 数据", "双精度或打包数据视图"),
            ("q0-q15", "NEON 向量寄存器", "128 位 SIMD 运算", "逆向多媒体/加密代码时常见"),
        ],
    },
    "AArch64": {
        "note": "AArch64 这里按常见 64 位 ARM 调用习惯整理，方便快速判断参数寄存器和保存寄存器。",
        "rows": [
            ("x0-x7 / w0-w7", "参数/返回值", "前 8 个整数参数，`x0` 常见返回值", "写 `wN` 会清零对应 `xN` 高 32 位"),
            ("x8 / w8", "特殊/中转", "间接返回值地址、syscall 编号等", "具体含义依平台而变"),
            ("x9-x15", "临时寄存器", "短期中转、表达式计算", "通常由调用者保存"),
            ("x16-x18", "平台/临时寄存器", "PLT、跳板、平台保留用途", "逆向时需结合平台 ABI 判断"),
            ("x19-x28", "保存寄存器", "长期保存局部状态、对象上下文", "通常由被调用者保存"),
            ("x29 / fp", "帧指针", "访问栈帧、局部变量", "函数序言/尾声里高频出现"),
            ("x30 / lr", "链接寄存器", "保存返回地址", "`ret` 常默认使用它"),
            ("sp / wsp", "栈指针", "函数栈空间管理", "写 `wsp` 同样会影响栈指针"),
            ("pc", "程序计数器", "当前执行位置", "通常通过 `b/bl/br/ret` 改变"),
            ("v0-v7", "SIMD/浮点参数", "浮点返回值、前几个 SIMD 参数", "`v0` 常见于返回值"),
            ("v8-v31", "SIMD/浮点寄存器", "向量和浮点临时值", "常见于 NEON 代码"),
            ("nzcv", "标志寄存器", "条件分支依赖的标志位", "受 `cmp/subs/adds` 等更新"),
        ],
    },
    "MIPS": {
        "note": "MIPS 这里按经典寄存器分组整理，方便快速判断参数、返回值和保存约定。",
        "rows": [
            ("$zero", "常量寄存器", "永远读为 0", "写入会被忽略"),
            ("$at", "汇编器临时", "伪指令展开时常用", "手改汇编时一般少直接使用"),
            ("$v0-$v1", "返回值寄存器", "函数返回值、syscall 结果", "`$v0` 也常作 syscall 编号"),
            ("$a0-$a3", "参数寄存器", "前 4 个参数", "逆向函数调用时最常关注"),
            ("$t0-$t9", "临时寄存器", "短期中转和表达式计算", "通常由调用者保存"),
            ("$s0-$s7", "保存寄存器", "长期保存局部状态", "通常由被调用者保存"),
            ("$gp", "全局指针", "全局数据访问", "位置相关代码里常见"),
            ("$sp", "栈指针", "函数栈顶、局部变量分配", "改动前应确认栈平衡"),
            ("$fp / $s8", "帧指针", "访问当前栈帧", "某些编译器把 `$s8` 作为帧指针"),
            ("$ra", "返回地址", "函数调用返回位置", "`jal` 会写入它"),
            ("$k0-$k1", "内核保留", "异常/内核路径", "用户态一般不主动使用"),
            ("HI / LO", "乘除法结果寄存器", "乘法高低位、除法商余数", "`mult/div` 后常配合 `mfhi/mflo`"),
        ],
    },
}


