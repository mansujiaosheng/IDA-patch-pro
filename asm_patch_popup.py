"""IDA 右键汇编修改插件。

功能概览：
1. 在反汇编右键菜单中提供“修改汇编”和“NOP”操作。
2. 打开自定义 Assemble 窗口，支持机器码预览、语法帮助、模板建议。
3. 对 IDA 显示用的栈变量表达式做自动折算，并为 x86/x64 提供 Keystone 兜底汇编。
"""

import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import idc
import idautils
import glob
import os
import re
import shutil
import subprocess
import sys


# 插件显示名称，以及两个右键动作的唯一 ID。
PLUGIN_NAME = "Asm Patch Popup"
ACTION_ASSEMBLE = "asm_patch_popup:assemble"
ACTION_NOP = "asm_patch_popup:nop"

# 助记符说明表：用于右侧提示面板展示当前指令的一般作用。
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
            ("call 401000h", "call target", "E8 xx xx xx xx", "5 bytes", "调用函数或子过程"),
            ("jmp short loc_401020", "jmp target", "EB xx / E9 xx xx xx xx", "2 or 5 bytes", "无条件跳转"),
            ("jz short loc_401030", "jcc target", "74 xx / 0F 84 xx xx xx xx", "2 or 6 bytes", "条件跳转，依赖标志位"),
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


def _current_ea(ctx):
    """Return the current EA from popup context, falling back to screen EA."""
    ea = getattr(ctx, "cur_ea", ida_idaapi.BADADDR)
    if ea == ida_idaapi.BADADDR:
        ea = ida_kernwin.get_screen_ea()
    return ea


def _selected_items(ctx):
    """Return selected disassembly items or the single current instruction."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        heads = list(idautils.Heads(start_ea, end_ea))
        if heads:
            return [(ea, ida_bytes.get_item_size(ea)) for ea in heads]
        return [(start_ea, end_ea - start_ea)]

    ea = _current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return [(ea, size)]


def _patch_region(ctx):
    """Return patch start, length, user-facing description, and selection state."""
    widget = getattr(ctx, "widget", None)
    has_selection, start_ea, end_ea = ida_kernwin.read_range_selection(widget)
    if has_selection and start_ea != ida_idaapi.BADADDR and end_ea > start_ea:
        return start_ea, end_ea - start_ea, "选中范围 0x%X - 0x%X" % (start_ea, end_ea), True

    ea = _current_ea(ctx)
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        size = 1
    return ea, size, "当前地址 0x%X" % ea, False


def _format_bytes_hex(buf):
    """Format raw bytes as upper-case hex pairs for UI display."""
    if not buf:
        return "(none)"
    return " ".join("%02X" % b for b in buf)


def _get_original_instruction_text(ea):
    """Return the disassembly text shown by IDA for the given address."""
    text = idc.GetDisasm(ea) or ""
    return text.strip()


def _sanitize_asm_line(text):
    """Strip trailing IDA comments so only pure assembly text remains."""
    return text.split(";", 1)[0].strip()


def _get_original_instruction_bytes(ea):
    """Read the original instruction bytes from the database."""
    size = ida_bytes.get_item_size(ea)
    if size <= 0:
        return b""
    buf = ida_bytes.get_bytes(ea, size)
    return bytes(buf) if buf else b""


def _get_original_entries(ctx):
    """Build metadata for each selected instruction line."""
    entries = []
    for ea, _ in _selected_items(ctx):
        text = _get_original_instruction_text(ea)
        asm = _sanitize_asm_line(text)
        entries.append(
            {
                "ea": ea,
                "text": text,
                "asm": asm,
                "bytes": _get_original_instruction_bytes(ea),
                "operand_infos": _build_operand_infos(ea, asm),
            }
        )
    return entries


def _join_entry_asm_lines(entries):
    """Join selected instruction lines into the editable assembly text."""
    return "\n".join(entry["asm"] for entry in entries if entry["asm"])


def _build_preview_infos_from_entries(entries):
    """Convert original instruction entries into preview-style structures."""
    infos = []
    for entry in entries:
        if entry["asm"]:
            infos.append({"line": entry["asm"], "bytes": entry["bytes"], "note": None})
    return infos


def _strip_size_prefix(op):
    """Remove `byte ptr`/`dword ptr`-style prefixes from an operand string."""
    return re.sub(
        r"(?i)\b(?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr\b\s*",
        "",
        op.strip(),
    ).strip()


def _split_size_prefix(op):
    """Split an operand into explicit size prefix and core operand body."""
    stripped = op.strip()
    m = re.match(
        r"(?is)^((?:byte|word|dword|qword|xmmword|ymmword|zmmword|tbyte)\s+ptr)\s+(.*)$",
        stripped,
    )
    if not m:
        return "", stripped
    return m.group(1), m.group(2).strip()


def _normalize_mem_operand(op):
    """Normalize a memory operand so equivalent spellings compare equal."""
    op = _strip_size_prefix(op).lower()
    return re.sub(r"\s+", "", op)


def _pointer_bits():
    """Return the current database pointer width."""
    return 64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else 32


def _sign_extend(value, bits):
    """Interpret the given integer as a signed value of `bits` width."""
    if value is None:
        return None
    mask = (1 << bits) - 1
    value &= mask
    sign_bit = 1 << (bits - 1)
    if value & sign_bit:
        value -= 1 << bits
    return value


def _format_hex_literal(value):
    """Format an integer as IDA-style hexadecimal text."""
    if value == 0:
        return "0"
    digits = "%X" % value
    if digits[0] in "ABCDEF":
        digits = "0" + digits
    return digits + "h"


def _is_registerish_mem_term(token, arch_key):
    """Check whether a memory term looks like a register/index component."""
    token = token.strip().lower()
    if not token:
        return False

    token = token.replace(" ", "")
    if token.startswith("-"):
        token = token[1:]
    if "*" in token:
        token = token.split("*", 1)[0]
    if ":" in token:
        token = token.rsplit(":", 1)[-1]

    return _register_hint(token, arch_key) is not None


def _rebuild_stack_operand_text(op_text, disp_value, arch_key):
    """Rewrite IDA stack-var text like `[rsp+198h+var_158]` into real offsets."""
    core = _strip_size_prefix(op_text)
    m = re.match(r"(?is)^(?P<prefix>[^[]*?)(?P<body>\[[^]]*\])(?P<suffix>.*)$", core)
    if not m:
        return core

    prefix = m.group("prefix").strip()
    body = m.group("body")[1:-1]
    suffix = m.group("suffix").strip()

    parts = []
    for match in re.finditer(r"([+-]?)\s*([^+-]+)", body):
        sign = match.group(1) or "+"
        term = match.group(2).strip()
        if _is_registerish_mem_term(term, arch_key):
            parts.append((sign, term))

    disp_bits = 32 if arch_key == "x86/x64" else _pointer_bits()
    disp = _sign_extend(int(disp_value), disp_bits)
    if disp is None:
        disp = 0

    body_text = ""
    for index, (sign, term) in enumerate(parts):
        if index == 0:
            body_text = term if sign != "-" else "-" + term
        else:
            body_text += ("-" if sign == "-" else "+") + term

    if disp != 0 or not body_text:
        disp_text = _format_hex_literal(abs(disp))
        if body_text:
            body_text += ("-" if disp < 0 else "+") + disp_text
        else:
            body_text = ("-" if disp < 0 else "") + disp_text

    result = "[%s]" % body_text
    if prefix:
        result = "%s%s" % (prefix, result)
    if suffix:
        result = "%s%s" % (result, suffix)
    return result


def _build_operand_infos(ea, asm):
    """Collect per-operand display text and assembler-safe rewritten forms."""
    arch_key = _processor_key()
    flags = ida_bytes.get_flags(ea)
    _, operands = _split_operands(asm)
    infos = []

    for index, operand in enumerate(operands):
        asm_operand = operand
        if (
            arch_key == "x86/x64"
            and "[" in operand
            and "]" in operand
            and ida_bytes.is_stkvar(flags, index)
        ):
            disp_value = idc.get_operand_value(ea, index)
            asm_operand = _rebuild_stack_operand_text(operand, disp_value, arch_key)
        infos.append(
            {
                "index": index,
                "display": operand,
                "normalized": _normalize_mem_operand(operand),
                "asm_operand": asm_operand,
            }
        )
    return infos


def _rewrite_line_for_assembly(line, arch_key, original_entry=None):
    """Rewrite user text into a more assembler-friendly form before assembly."""
    if not original_entry:
        return line

    mnem, operands = _split_operands(line)
    if not mnem or not operands:
        return line

    operand_infos = original_entry.get("operand_infos") or []
    if not operand_infos:
        return line

    rewritten = []
    for operand in operands:
        size_prefix, core = _split_size_prefix(operand)
        normalized = _normalize_mem_operand(core)
        replacement = None
        for info in operand_infos:
            if info.get("normalized") == normalized and info.get("asm_operand"):
                replacement = info["asm_operand"]
                break
        if replacement is None:
            rewritten.append(operand)
            continue
        if size_prefix:
            rewritten.append("%s %s" % (size_prefix, replacement))
        else:
            rewritten.append(replacement)

    return "%s %s" % (mnem, ", ".join(rewritten))


def _infer_operand_size_keyword(op):
    """Infer operand width keyword such as byte/dword/qword from text."""
    lower = op.strip().lower()
    for prefix in ("byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword", "tbyte"):
        if re.search(r"(?i)\b%s\s+ptr\b" % prefix, lower):
            return prefix

    reg = lower
    if reg in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl"):
        return "byte"
    if re.fullmatch(r"r(1[0-5]|[8-9])b", reg):
        return "byte"
    if reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return "word"
    if re.fullmatch(r"r(1[0-5]|[8-9])w", reg):
        return "word"
    if reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        return "dword"
    if re.fullmatch(r"r(1[0-5]|[8-9])d", reg):
        return "dword"
    if reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        return "qword"
    if re.fullmatch(r"r(1[0-5]|[8-9])", reg):
        return "qword"
    if re.fullmatch(r"xmm([0-9]|1[0-5])", reg):
        return "xmmword"
    if re.fullmatch(r"ymm([0-9]|1[0-5])", reg):
        return "ymmword"
    if re.fullmatch(r"zmm([0-9]|1[0-5]|2[0-9]|3[01])", reg):
        return "zmmword"
    return None


def _infer_memory_size_keyword(original_entry, current_dst):
    """Infer the required `ptr` size for a memory-destination rewrite."""
    if not original_entry:
        return None

    original_asm = original_entry.get("asm", "")
    _, ops = _split_operands(original_asm)
    if not ops:
        return None

    wanted = _normalize_mem_operand(current_dst)
    mem_ops = [op for op in ops if "[" in op and "]" in op]
    if not mem_ops:
        return None

    chosen = None
    for op in mem_ops:
        if _normalize_mem_operand(op) == wanted:
            chosen = op
            break
    if chosen is None and len(mem_ops) == 1:
        chosen = mem_ops[0]
    if chosen is None:
        return None

    explicit = _infer_operand_size_keyword(chosen)
    if explicit:
        return explicit

    for op in ops:
        if op == chosen:
            continue
        inferred = _infer_operand_size_keyword(op)
        if inferred:
            return inferred

    mnem = _extract_mnemonic(original_asm)
    if mnem in ("movaps", "movups", "movdqa", "movdqu", "pxor", "xorps"):
        return "xmmword"
    return None


def _first_nonempty_line(text):
    """Return the first non-empty line from a multi-line editor string."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _extract_mnemonic(text):
    """Extract the mnemonic from the first meaningful line of assembly text."""
    line = _first_nonempty_line(text)
    if not line:
        return ""
    line = line.split(";", 1)[0].strip()
    tokens = line.split()
    if not tokens:
        return ""
    first = tokens[0].lower()
    if first in ("rep", "repe", "repz", "repne", "repnz", "lock") and len(tokens) >= 2:
        second = tokens[1].lower()
        combined = "%s %s" % (first, second)
        if combined in MNEMONIC_HINTS:
            return combined
        if second in MNEMONIC_HINTS:
            return second
        return combined
    return first


def _extract_registers(text, arch_key):
    """Extract registers mentioned in the current line for hint display."""
    line = _first_nonempty_line(text).lower()
    if not line:
        return []

    found = []
    seen = set()
    for token in re.findall(r"\$[a-z0-9]+|[a-z][a-z0-9()]*", line):
        if token in seen:
            continue
        if _register_hint(token, arch_key):
            found.append(token)
            seen.add(token)
    return found


def _split_operands(text):
    """Split a single instruction into mnemonic and operand list."""
    line = _first_nonempty_line(text)
    if not line:
        return "", []

    code = line.split(";", 1)[0].strip()
    parts = code.split(None, 1)
    if not parts:
        return "", []
    if len(parts) == 1:
        return parts[0].lower(), []

    ops = []
    current = []
    depth = 0
    for ch in parts[1]:
        if ch in "[({":
            depth += 1
        elif ch in "])}" and depth > 0:
            depth -= 1

        if ch == "," and depth == 0:
            operand = "".join(current).strip()
            if operand:
                ops.append(operand)
            current = []
            continue
        current.append(ch)

    operand = "".join(current).strip()
    if operand:
        ops.append(operand)
    return parts[0].lower(), ops


def _is_zero_literal(text):
    """Return whether the text represents zero in decimal or hex form."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value in ("0", "+0", "-0", "0h", "+0h", "-0h", "0x0", "+0x0", "-0x0"):
        return True
    if value.startswith(("0x", "+0x", "-0x")):
        value = value.replace("+", "").replace("-", "")
        return value[2:] and set(value[2:]) == {"0"}
    if value.endswith("h"):
        value = value[:-1].replace("+", "").replace("-", "")
        return value and set(value) == {"0"}
    return value.replace("+", "").replace("-", "").isdigit() and set(value.replace("+", "").replace("-", "")) == {"0"}


def _is_immediate_literal(text):
    """Return whether the text looks like an immediate literal value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return False
    if value.startswith(("0x", "+0x", "-0x")):
        body = value.replace("+", "").replace("-", "")[2:]
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    if value.endswith("h"):
        body = value[:-1].replace("+", "").replace("-", "")
        return bool(body) and all(ch in "0123456789abcdef" for ch in body)
    value = value.replace("+", "").replace("-", "")
    return value.isdigit()


def _parse_immediate_value(text):
    """Parse a decimal/hex literal and return its integer value."""
    value = text.strip().lower().replace("_", "")
    if not value:
        return None
    sign = 1
    if value[0] == "+":
        value = value[1:]
    elif value[0] == "-":
        sign = -1
        value = value[1:]
    if not value:
        return None
    try:
        if value.startswith("0x"):
            return sign * int(value, 16)
        if value.endswith("h"):
            return sign * int(value[:-1], 16)
        return sign * int(value, 10)
    except ValueError:
        return None


def _canonical_x64_reg(text):
    """Map partial x64 register views back to their 64-bit canonical register."""
    reg = text.strip().lower()
    mapping = {
        "rax": "rax", "eax": "rax", "ax": "rax", "ah": "rax", "al": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bh": "rbx", "bl": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "ch": "rcx", "cl": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dh": "rdx", "dl": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if reg in mapping:
        return mapping[reg]
    m = re.fullmatch(r"r(1[0-5]|[8-9])(?:d|w|b)?", reg)
    if m:
        return "r%s" % m.group(1)
    return None


def _to_x64_reg32(text):
    """Map an x64 register to its 32-bit form for shorter rewrite templates."""
    base = _canonical_x64_reg(text)
    if not base:
        return None
    mapping = {
        "rax": "eax",
        "rbx": "ebx",
        "rcx": "ecx",
        "rdx": "edx",
        "rsi": "esi",
        "rdi": "edi",
        "rbp": "ebp",
        "rsp": "esp",
    }
    if base in mapping:
        return mapping[base]
    m = re.fullmatch(r"r(1[0-5]|[8-9])", base)
    if m:
        return "r%sd" % m.group(1)
    return None


def _fallback_assembly_candidates(line, arch_key, original_entry=None):
    """Generate compatibility rewrites when the original text may fail to assemble."""
    mnem, operands = _split_operands(line)
    if not mnem:
        return []

    candidates = []
    if arch_key == "x86/x64" and mnem == "mov" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        dst32 = _to_x64_reg32(dst)
        value = _parse_immediate_value(src)
        if dst32 and value is not None:
            if value == 0:
                candidates.append(
                    (
                        "xor %s, %s" % (dst32, dst32),
                        "兼容模板: 用 `xor %s, %s` 实现清零。"
                        % (dst32, dst32),
                    )
                )
                candidates.append(
                    (
                        "mov %s, 0" % dst32,
                        "兼容模板: 用 `mov %s, 0` 代替 64 位立即数写法。"
                        % dst32,
                    )
                )
            elif 0 <= value <= 0xFFFFFFFF:
                candidates.append(
                    (
                        "mov %s, %s" % (dst32, src),
                        "兼容模板: 用 `mov %s, %s` 代替，它会清零高 32 位。"
                        % (dst32, src),
                    )
                )
        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            size_kw = _infer_memory_size_keyword(original_entry, dst)
            if size_kw in ("byte", "word", "dword", "qword"):
                dst_clean = _strip_size_prefix(dst)
                candidates.append(
                    (
                        "mov %s ptr %s, %s" % (size_kw, dst_clean, src),
                        "兼容模板: 对内存写立即数时自动补上 `%s ptr` 大小限定。"
                        % size_kw,
                    )
                )

    if arch_key == "x86/x64" and mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        scalar_size = _infer_operand_size_keyword(dst)
        if "[" in dst and "]" in dst and scalar_size in ("byte", "word", "dword", "qword") and _is_immediate_literal(src):
            dst_clean = _strip_size_prefix(dst)
            candidates.append(
                (
                    "mov %s ptr %s, %s" % (scalar_size, dst_clean, src),
                    "兼容模板: `%s` 不能直接把立即数写入内存，已按标量 `mov %s ptr` 重写。"
                    % (mnem, scalar_size),
                )
            )
    return candidates


def _build_template_suggestions(current_text, current_bytes, region_size, arch_key, original_entry=None):
    """Build right-panel rewrite suggestions for the current instruction line."""
    mnem, operands = _split_operands(current_text)
    if not mnem:
        return []

    overflow = current_bytes is not None and len(current_bytes) > region_size
    suggestions = []

    if mnem == "mov" and len(operands) >= 2 and arch_key == "x86/x64":
        dst, src = operands[0], operands[1]
        dst64 = _canonical_x64_reg(dst)
        dst32 = _to_x64_reg32(dst)
        size_kw = _infer_memory_size_keyword(original_entry, dst)

        if dst64 and _is_zero_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时优先模板: `xor %s, %s`。它能把 `%s` 清零，通常明显短于 `mov %s, 0`。"
                    % (dst32 or dst, dst32 or dst, dst64, dst)
                )
            suggestions.append(
                "固定模板: `xor %s, %s`。这是把寄存器置 0 的首选短写法。"
                % (dst32 or dst, dst32 or dst)
            )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, 0`。写 32 位寄存器时会自动清零对应 64 位高半部分。"
                    % dst32
                )
            suggestions.append(
                "如果必须保留 `mov %s, 0` 这种完整写法，请扩大选区或接受继续覆盖后续字节。"
                % dst
            )
            return suggestions

        if dst64 and _is_immediate_literal(src):
            if overflow:
                suggestions.append(
                    "长度不够时可先尝试更短模板: `mov %s, %s`。x64 下写 32 位寄存器会清零高 32 位。"
                    % (dst32 or dst, src)
                )
            if dst32:
                suggestions.append(
                    "固定模板: `mov %s, %s`。适合你只是想把一个立即数放进寄存器且不关心高 32 位原值的场景。"
                    % (dst32, src)
                )
            suggestions.append(
                "如果要把更大的立即数完整写进 `%s`，最稳的方法仍是扩大选区。"
                % dst
            )
            return suggestions

        if dst64 and _canonical_x64_reg(src):
            suggestions.append(
                "寄存器到寄存器的 `mov` 通常已经比较短；如果这里仍超长，更多是当前地址空间不够，建议扩大选区。"
            )
            suggestions.append(
                "如果你的真实目的只是清空 `%s`，可直接改成 `xor %s, %s`。"
                % (dst64, dst32 or dst, dst32 or dst)
            )
            return suggestions

        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            if size_kw in ("byte", "word", "dword", "qword"):
                suggestions.append(
                    "固定模板: `mov %s ptr %s, %s`。对内存写立即数时，通常必须显式写出大小。"
                    % (size_kw, _strip_size_prefix(dst), src)
                )
            else:
                suggestions.append(
                    "对内存写立即数时，通常必须显式写出大小，例如 `mov byte/dword/qword ptr [mem], imm`。"
                )
            return suggestions

        suggestions.append("`mov` 涉及内存寻址时，长度往往由地址编码决定，最直接的办法通常是扩大选区。")
        suggestions.append("如果你只是想把寄存器清零，优先考虑 `xor <reg32>, <reg32>` 这类短模板。")
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key in ("ARM/Thumb", "AArch64"):
        dst, src = operands[0], operands[1]
        suggestions.append("ARM/AArch64 的 `mov` 长度通常更稳定；若超出范围，多半需要扩大选区而不是换助记符。")
        if _is_zero_literal(src):
            suggestions.append("固定模板: `eor %s, %s, %s`。当你只是想清零寄存器时可作为等价写法。" % (dst, dst, dst))
        return suggestions

    if mnem == "mov" and len(operands) >= 2 and arch_key == "MIPS":
        dst, src = operands[0], operands[1]
        suggestions.append("MIPS 的 `mov/li` 经常是伪指令，可能展开成多条真实指令；超长时应优先检查是否需要扩大选区。")
        if _is_zero_literal(src):
            suggestions.append("固定模板: `move %s, $zero`。当你只是想置零寄存器时可直接使用。" % dst)
        return suggestions

    if mnem == "lea" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `lea %s, [base+index*scale+disp]`。适合做地址计算，而不是读内存。" % dst)
        suggestions.append("如果你的真实目的其实是取内存里的值，应改用 `mov %s, %s`。" % (dst, src))
        return suggestions

    if mnem == "xor" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `xor dst, src`。适合做按位异或。")
        if left.lower() == right.lower():
            suggestions.append("当前写法也是经典清零模板: `xor %s, %s`。" % (left, right))
        else:
            suggestions.append("如果你的真实目的只是清零 `%s`，可改成 `xor %s, %s`。" % (left, left, left))
        return suggestions

    if mnem == "add" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `add %s, %s`。适合给目标加上寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想加 1，可考虑 `inc %s`，但要注意它与 `add` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "sub" and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        suggestions.append("固定模板: `sub %s, %s`。适合从目标减去寄存器或立即数。" % (dst, src))
        suggestions.append("如果你只是想减 1，可考虑 `dec %s`，但要注意它与 `sub` 的标志位行为并不完全相同。" % dst)
        return suggestions

    if mnem == "cmp" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `cmp %s, %s`。适合做大小/相等比较，然后配合条件跳转。" % (left, right))
        suggestions.append("常见配套模板: `cmp %s, %s` 后接 `jz/jnz/jg/jl/...`。" % (left, right))
        return suggestions

    if mnem == "test" and len(operands) >= 2:
        left, right = operands[0], operands[1]
        suggestions.append("固定模板: `test %s, %s`。适合做按位测试，只更新标志位，不保存结果。" % (left, right))
        suggestions.append("常见零值判断模板: `test reg, reg` 后接 `jz/jnz`。")
        return suggestions

    if mnem in ("jz", "je", "jnz", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "js", "jns") and operands:
        suggestions.append("固定模板: `%s target`。条件跳转通常依赖前面的 `cmp/test` 结果。" % mnem)
        suggestions.append("常见配套模板: 先 `cmp/test`，再 `%s label`。" % mnem)
        return suggestions

    if mnem == "jmp" and operands:
        suggestions.append("固定模板: `jmp target`。无条件跳转会直接改变控制流。")
        suggestions.append("如果目标是寄存器，也可用 `jmp reg` 做间接跳转。")
        return suggestions

    if mnem == "call" and operands:
        suggestions.append("固定模板: `call target`。直接调用函数或子过程。")
        suggestions.append("如果目标在寄存器里，也可用 `call reg`。")
        return suggestions

    if mnem == "push" and operands:
        suggestions.append("固定模板: `push src`。常用于保存寄存器、传参或构造栈数据。")
        if arch_key == "x86/x64":
            suggestions.append("常见配套模板: `push imm` / `pop reg`，可把一个立即数放进寄存器。")
        return suggestions

    if mnem == "pop" and operands:
        suggestions.append("固定模板: `pop dst`。常用于恢复寄存器或从栈中取值。")
        suggestions.append("常见配套模板: `push src` 后接 `pop dst`。")
        return suggestions

    if mnem == "ret":
        suggestions.append("固定模板: `ret`。直接从当前函数返回。")
        suggestions.append("如果调用约定要求回收参数，某些平台会见到 `ret imm`。")
        return suggestions

    if mnem == "nop":
        suggestions.append("固定模板: `nop`。适合补齐长度、屏蔽逻辑或做对齐填充。")
        suggestions.append("如果需要覆盖更长范围，可以连续使用多条 `nop`。")
        return suggestions

    if mnem in ("and", "or") and len(operands) >= 2:
        suggestions.append("固定模板: `%s %s, %s`。适合位运算、掩码处理和标志位修改。" % (mnem, operands[0], operands[1]))
        return suggestions

    if mnem in ("movaps", "movups", "movdqa", "movdqu") and len(operands) >= 2:
        dst, src = operands[0], operands[1]
        vector_dst = _strip_size_prefix(dst)
        suggestions.append(
            "`%s` 只能在向量寄存器和对应内存块之间搬运，不能直接把立即数当源操作数。"
            % mnem
        )
        if "[" in dst and "]" in dst and _is_immediate_literal(src):
            suggestions.append(
                "如果你想把这块 16 字节内存清零，常见模板是 `pxor xmm0, xmm0` 后再 `%s xmmword ptr %s, xmm0`。"
                % (mnem, vector_dst)
            )
            suggestions.append(
                "如果你只是想给其中某个标量槽写入 1，请改用 `mov byte/word/dword/qword ptr %s, 1` 并明确大小。"
                % vector_dst
            )
        return suggestions

    if mnem in ("imul", "mul", "div", "idiv"):
        suggestions.append("这类乘除法指令通常受特定寄存器约束，修改前应先确认调用约定和结果寄存器。")
        if arch_key == "x86/x64":
            suggestions.append("x86/x64 下常见固定模板会隐式使用 `rax/rdx`。")
        return suggestions

    suggestions.append("当前助记符 `%s` 暂无专门模板，但右侧的原机器码、寄存器作用和长度提示仍可作为改写参考。" % mnem)
    return suggestions

    return suggestions


def _length_warning_text(patch_size, region_size, has_selection, start_ea):
    """Return a user-facing summary of length fit or overflow."""
    if patch_size == region_size:
        return "长度匹配当前可覆盖范围。"
    if patch_size < region_size:
        return "新汇编比原范围短 %d bytes，剩余部分会自动补 NOP。" % (region_size - patch_size)

    overflow_end = start_ea + patch_size - 1
    if has_selection:
        return (
            "新汇编超出选区 %d bytes，当前不会允许写入；"
            " 需要扩大选区到至少 0x%X。"
            % (patch_size - region_size, overflow_end)
        )
    return (
        "新汇编超出当前指令 %d bytes，将继续覆盖到 0x%X。"
        % (patch_size - region_size, overflow_end)
    )


def _build_hint_text(original_entries, current_text, preview_bytes, preview_infos, region_size, has_selection, start_ea, arch_key):
    """Assemble the full right-side help panel text."""
    current_lines = [_sanitize_asm_line(line) for line in current_text.splitlines()]
    current_lines = [line for line in current_lines if line]
    preview_infos = preview_infos or []

    line_count = max(len(original_entries), len(current_lines), len(preview_infos), 1)
    lines = []

    if line_count > 1:
        lines.append(
            "原始行数: %d | 当前编辑行数: %d"
            % (len(original_entries), len(current_lines))
        )
        if preview_bytes is not None:
            lines.append("总长度提示: %s" % _length_warning_text(len(preview_bytes), region_size, has_selection, start_ea))
        elif current_text.strip():
            lines.append("总长度提示: 当前输入还无法成功汇编")

    for index in range(line_count):
        original_entry = original_entries[index] if index < len(original_entries) else None
        current_line = current_lines[index] if index < len(current_lines) else ""
        preview_info = preview_infos[index] if index < len(preview_infos) else None

        if lines:
            lines.append("")
        title = "第 %d 行" % (index + 1)
        if original_entry:
            title += " @ 0x%X" % original_entry["ea"]
        lines.append(title)

        if original_entry:
            lines.append("原指令: %s" % (original_entry["text"] or "(unknown)"))
            lines.append("原机器码: %s" % _format_bytes_hex(original_entry["bytes"]))
        else:
            lines.append("原指令: (无)")
            lines.append("原机器码: (none)")

        if current_line:
            lines.append("当前编辑: %s" % current_line)
            if preview_info:
                lines.append("新机器码预览: %s" % _format_bytes_hex(preview_info["bytes"]))
                if preview_info.get("note"):
                    lines.append("兼容说明: %s" % preview_info["note"])
            else:
                lines.append("新机器码预览: 当前输入还无法成功汇编")

        source_text = current_line or (original_entry["asm"] if original_entry else "")
        hint_key = _extract_mnemonic(source_text)
        if hint_key:
            lines.append("指令说明: %s" % MNEMONIC_HINTS.get(hint_key, "该助记符暂无内置说明。"))

        regs = _extract_registers(source_text, arch_key)
        if regs:
            lines.append("寄存器提示:")
            for reg in regs:
                lines.append("%s: %s" % (reg, _register_hint(reg, arch_key) or "暂无说明。"))

        per_line_region = len(original_entry["bytes"]) if original_entry and original_entry["bytes"] else region_size
        per_line_bytes = preview_info["bytes"] if preview_info else None
        suggestions = _build_template_suggestions(source_text, per_line_bytes, per_line_region, arch_key, original_entry)
        if suggestions:
            lines.append("模板建议:")
            for suggestion in suggestions:
                lines.append("- %s" % suggestion)

    return "\n".join(lines)


def _processor_key():
    """Map IDA processor info to the plugin's architecture categories."""
    proc_name = idc.get_inf_attr(idc.INF_PROCNAME)
    is_64bit = bool(idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT)

    if proc_name == "metapc":
        return "x86/x64"
    if proc_name == "ARM":
        return "AArch64" if is_64bit else "ARM/Thumb"
    if proc_name in ("mips", "mipsb", "mipsl"):
        return "MIPS"
    return "x86/x64"


def _try_assemble_line(ea, text):
    """Try assembling one line with IDA's built-in assembler."""
    prev_batch = idc.batch(1)
    try:
        ok, result = idautils.Assemble(ea, text)
    finally:
        idc.batch(prev_batch)

    if ok:
        return bytes(result)
    return None


def _can_try_keystone_on_line(text, arch_key):
    """Check whether a line is simple enough for Keystone fallback assembly."""
    if arch_key != "x86/x64":
        return False

    mnem, operands = _split_operands(text)
    if not mnem:
        return False

    allowed_words = {
        "byte",
        "word",
        "dword",
        "qword",
        "xmmword",
        "ymmword",
        "zmmword",
        "tbyte",
        "ptr",
        "short",
        "near",
        "far",
    }

    for operand in operands:
        scan = operand.lower()
        scan = re.sub(r"(?i)\b0x[0-9a-f]+\b", " ", scan)
        scan = re.sub(r"(?i)\b[0-9][0-9a-f]*h\b", " ", scan)
        scan = re.sub(r"\b\d+\b", " ", scan)
        for token in re.findall(r"\$[a-z_][a-z0-9_]*|[a-z_][a-z0-9_]*", scan):
            if token in allowed_words:
                continue
            if _register_hint(token, arch_key):
                continue
            return False
    return True


def _load_keystone_module():
    """Import Keystone from IDA Python or common Windows Python installs."""
    try:
        import keystone  # type: ignore

        return keystone
    except Exception:
        pass

    candidates = []

    def add_dir(path):
        if not path:
            return
        path = os.path.normpath(path)
        if os.path.isdir(path) and path not in candidates:
            candidates.append(path)

    exe = sys.executable or ""
    if exe:
        add_dir(os.path.join(os.path.dirname(exe), "Lib", "site-packages"))

    for env_name in ("LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        for root in glob.glob(os.path.join(base, "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))
        for root in glob.glob(os.path.join(base, "Programs", "Python", "Python*")):
            add_dir(os.path.join(root, "Lib", "site-packages"))

    for path in candidates:
        if path not in sys.path:
            sys.path.append(path)
        try:
            import keystone  # type: ignore

            return keystone
        except Exception:
            continue

    return None


def _try_assemble_line_keystone(ea, text, arch_key):
    """Try assembling one line with Keystone, locally or via system Python."""
    if not _can_try_keystone_on_line(text, arch_key):
        return None

    keystone = _load_keystone_module()
    if keystone is not None:
        try:
            mode = keystone.KS_MODE_64 if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else keystone.KS_MODE_32
            ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
            encoded, _ = ks.asm(text, addr=ea, as_bytes=True)
            if encoded:
                return bytes(encoded)
        except Exception:
            pass

    mode_name = "64" if (idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT) else "32"
    helper = (
        "import sys\n"
        "from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64\n"
        "mode = KS_MODE_64 if sys.argv[1] == '64' else KS_MODE_32\n"
        "ks = Ks(KS_ARCH_X86, mode)\n"
        "enc, _ = ks.asm(sys.argv[3], addr=int(sys.argv[2], 0), as_bytes=True)\n"
        "print(bytes(enc).hex())\n"
    )
    for launcher in (["python"], ["py", "-3"]):
        if shutil.which(launcher[0]) is None:
            continue
        try:
            proc = subprocess.run(
                launcher + ["-c", helper, mode_name, hex(ea), text],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            continue

        if proc.returncode != 0:
            continue

        hex_text = (proc.stdout or "").strip()
        if not hex_text:
            continue
        try:
            return bytes.fromhex(hex_text)
        except ValueError:
            continue

    return None


def _assemble_bytes(ea, text, arch_key, original_entry=None):
    """Assemble one line after trying rewritten text and compatibility fallbacks."""
    prepared = _rewrite_line_for_assembly(text, arch_key, original_entry)
    prepared_note = None
    if prepared != text:
        prepared_note = "自动将栈变量表达式折算为真实偏移后汇编。"

    attempts = []
    seen = set()
    if prepared not in seen:
        attempts.append((prepared, prepared_note))
        seen.add(prepared)

    for candidate, note in _fallback_assembly_candidates(prepared, arch_key, original_entry):
        candidate = _rewrite_line_for_assembly(candidate, arch_key, original_entry)
        if candidate in seen:
            continue
        merged_note = note
        if prepared_note:
            merged_note = (
                prepared_note
                if not note
                else "%s %s" % (prepared_note, note)
            )
        attempts.append((candidate, merged_note))
        seen.add(candidate)

    if text not in seen:
        attempts.append((text, None))
        seen.add(text)

    for candidate, note in attempts:
        buf = _try_assemble_line_keystone(ea, candidate, arch_key)
        if buf is not None:
            if note:
                return buf, "%s 使用 Keystone 兼容汇编。" % note
            return buf, "使用 Keystone 兼容汇编。"

    for candidate, note in attempts:
        buf = _try_assemble_line(ea, candidate)
        if buf is not None:
            return buf, note

    raise RuntimeError("无法汇编: %s" % text)


def _assemble_multiline(ea, text, arch_key, original_entries=None):
    """Assemble multiple lines and preserve per-line preview metadata."""
    chunks = []
    notes = []
    line_infos = []
    current_ea = ea
    lines = [_sanitize_asm_line(line) for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        raise RuntimeError("请输入至少一条汇编指令。")

    for index, line in enumerate(lines):
        original_entry = (
            original_entries[index]
            if original_entries is not None and index < len(original_entries)
            else None
        )
        chunk, note = _assemble_bytes(current_ea, line, arch_key, original_entry)
        chunks.append(chunk)
        if note:
            notes.append(note)
        line_infos.append({"line": line, "bytes": chunk, "note": note})
        current_ea += len(chunk)
    return b"".join(chunks), notes, line_infos


def _build_nop_bytes(ea, size):
    """Assemble enough NOP instructions to fill the requested byte count."""
    parts = []
    remaining = size
    current_ea = ea
    arch_key = _processor_key()

    while remaining > 0:
        nop_bytes, _ = _assemble_bytes(current_ea, "nop", arch_key)
        if not nop_bytes:
            raise RuntimeError("NOP 汇编结果为空。")
        if len(nop_bytes) > remaining:
            raise RuntimeError(
                "无法用当前处理器的 NOP 指令精确覆盖地址 0x%X 处的 %d 字节。"
                % (ea, size)
            )
        parts.append(nop_bytes)
        current_ea += len(nop_bytes)
        remaining -= len(nop_bytes)

    return b"".join(parts)


def _patch_instruction(ea, patch_bytes):
    """Patch one instruction-sized region and recreate the instruction there."""
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)
    ida_auto.auto_recreate_insn(ea)


def _patch_bytes_as_code(ea, patch_bytes):
    """Patch raw bytes and ask IDA to recreate code over the whole range."""
    end_ea = ea + len(patch_bytes)
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, len(patch_bytes))
    ida_bytes.patch_bytes(ea, patch_bytes)

    current = ea
    while current < end_ea:
        length = ida_auto.auto_recreate_insn(current)
        if length <= 0:
            current += 1
        else:
            current += length

    ida_kernwin.refresh_idaview_anyway()


def _load_qt():
    """Import PySide6 lazily so the module loads cleanly inside IDA."""
    from PySide6 import QtCore, QtGui, QtWidgets

    return QtCore, QtGui, QtWidgets


class ReferenceTableDialog:
    """Shared searchable table dialog used by syntax and register references."""

    def __init__(self, title, note_text, headers, rows, monospace_columns=None, parent=None):
        """Build a generic filterable reference table."""
        QtCore, QtGui, QtWidgets = _load_qt()
        monospace_columns = set(monospace_columns or [])

        self.dialog = QtWidgets.QDialog(parent)
        self.dialog.setWindowTitle(title)
        self.dialog.resize(1080, 520)
        self._rows = list(rows)
        self._QtWidgets = QtWidgets
        self._QtGui = QtGui

        layout = QtWidgets.QVBoxLayout(self.dialog)

        note = QtWidgets.QLabel(note_text, self.dialog)
        note.setWordWrap(True)
        layout.addWidget(note)

        self.search_edit = QtWidgets.QLineEdit(self.dialog)
        self.search_edit.setPlaceholderText("输入关键字过滤，例如 mov / rsp / xmm0 / return / 参数")
        self.search_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.search_edit)

        self.table = QtWidgets.QTableWidget(self.dialog)
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(self._rows))
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)

        monospace_font = QtGui.QFont("Consolas")
        for row_index, row in enumerate(self._rows):
            for col_index, value in enumerate(row):
                item = QtWidgets.QTableWidgetItem(value)
                if col_index in monospace_columns:
                    item.setFont(monospace_font)
                self.table.setItem(row_index, col_index, item)

        header = self.table.horizontalHeader()
        for col_index in range(max(0, len(headers) - 1)):
            header.setSectionResizeMode(col_index, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(len(headers) - 1, QtWidgets.QHeaderView.Stretch)
        layout.addWidget(self.table)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close, parent=self.dialog)
        buttons.rejected.connect(self.dialog.reject)
        buttons.accepted.connect(self.dialog.accept)
        layout.addWidget(buttons)

    def _apply_filter(self, text):
        """Hide rows that do not match the current search keyword."""
        needle = (text or "").strip().lower()
        for row_index, row in enumerate(self._rows):
            haystack = " ".join(row).lower()
            self.table.setRowHidden(row_index, bool(needle) and needle not in haystack)

    def exec(self):
        """Show the reference dialog modally."""
        return self.dialog.exec()


class SyntaxHelpDialog:
    """Architecture-specific syntax quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the quick reference table for the selected architecture."""
        info = ARCH_SYNTAX_HELP[category]
        self.reference = ReferenceTableDialog(
            "汇编语法帮助 - %s" % category,
            info["note"],
            ["示例", "语法", "典型十六进制", "典型字节长度", "含义"],
            info["rows"],
            monospace_columns=(0, 1, 2),
            parent=parent,
        )

    def exec(self):
        """Show the syntax help dialog modally."""
        return self.reference.exec()


class RegisterHelpDialog:
    """Architecture-specific register quick reference dialog."""

    def __init__(self, category, parent=None):
        """Build the register reference table for the selected architecture."""
        info = ARCH_REGISTER_HELP[category]
        self.reference = ReferenceTableDialog(
            "寄存器速查表 - %s" % category,
            info["note"],
            ["寄存器", "类别", "常见用途", "补充说明"],
            info["rows"],
            monospace_columns=(0,),
            parent=parent,
        )

    def exec(self):
        """Show the register help dialog modally."""
        return self.reference.exec()


class AssemblePatchDialog:
    """Main assemble/preview/apply dialog opened from the popup menu."""

    def __init__(self, ctx):
        """Initialize dialog state from the current disassembly selection."""
        QtCore, QtGui, QtWidgets = _load_qt()
        self.QtWidgets = QtWidgets
        self.ctx = ctx
        self.arch_key = _processor_key()
        (
            self.start_ea,
            self.region_size,
            self.region_desc,
            self.has_selection,
        ) = _patch_region(ctx)

        self.dialog = QtWidgets.QDialog()
        self.dialog.setWindowTitle("Assemble")
        self.dialog.resize(1080, 460)

        # 原始上下文：用于回显、长度比较、栈变量折算和模板建议。
        self.original_entries = _get_original_entries(ctx)
        self.original_text = "\n".join(entry["text"] for entry in self.original_entries if entry["text"])
        self.original_asm_text = _join_entry_asm_lines(self.original_entries)
        self.original_bytes = b"".join(entry["bytes"] for entry in self.original_entries)

        # 当前预览状态：仅在最近一次预览成功时与编辑框内容同步。
        self.preview_text = self.original_asm_text
        self.preview_bytes = self.original_bytes
        self.preview_infos = _build_preview_infos_from_entries(self.original_entries)

        root = QtWidgets.QVBoxLayout(self.dialog)

        target = QtWidgets.QLabel(
            "目标: %s | 可覆盖大小: %d bytes" % (self.region_desc, self.region_size),
            self.dialog,
        )
        root.addWidget(target)

        note = QtWidgets.QLabel(
            "说明: 输入一条或多条汇编。若结果小于目标范围，剩余字节会自动填充为 NOP。",
            self.dialog,
        )
        note.setWordWrap(True)
        root.addWidget(note)

        body = QtWidgets.QHBoxLayout()

        self.editor = QtWidgets.QPlainTextEdit(self.dialog)
        self.editor.setPlaceholderText("例如:\nmov eax, 1\nxor ecx, ecx")
        font = QtGui.QFont("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        self.editor.setFont(font)
        body.addWidget(self.editor, 3)

        self.hint_panel = QtWidgets.QPlainTextEdit(self.dialog)
        self.hint_panel.setReadOnly(True)
        self.hint_panel.setFont(font)
        body.addWidget(self.hint_panel, 2)
        root.addLayout(body)

        toolbar = QtWidgets.QHBoxLayout()
        self.status = QtWidgets.QLabel("当前未输入汇编。", self.dialog)
        toolbar.addWidget(self.status, 1)

        self.preview_btn = QtWidgets.QPushButton("预览机器码", self.dialog)
        self.preview_btn.clicked.connect(self._preview_machine_code)
        toolbar.addWidget(self.preview_btn)

        self.syntax_btn = QtWidgets.QToolButton(self.dialog)
        self.syntax_btn.setText("语法")
        self.syntax_btn.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.syntax_btn.setMenu(self._build_syntax_menu())
        toolbar.addWidget(self.syntax_btn)

        self.register_btn = QtWidgets.QToolButton(self.dialog)
        self.register_btn.setText("寄存器")
        self.register_btn.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.register_btn.setMenu(self._build_register_menu())
        toolbar.addWidget(self.register_btn)
        root.addLayout(toolbar)

        buttons = QtWidgets.QDialogButtonBox(self.dialog)
        self.apply_btn = buttons.addButton("应用", QtWidgets.QDialogButtonBox.AcceptRole)
        self.cancel_btn = buttons.addButton("取消", QtWidgets.QDialogButtonBox.RejectRole)
        self.apply_btn.clicked.connect(self._apply_patch)
        self.cancel_btn.clicked.connect(self.dialog.reject)
        root.addWidget(buttons)
        self.editor.setPlainText(self.original_asm_text)
        self.status.setText("已载入当前指令。点击“预览机器码”或直接“应用”。")
        self.editor.textChanged.connect(self._on_text_changed)
        self._refresh_context_panel()

    def _build_syntax_menu(self):
        """Create the quick reference dropdown menu."""
        _, _, QtWidgets = _load_qt()
        menu = QtWidgets.QMenu(self.dialog)

        current_key = _processor_key()
        current_action = menu.addAction("当前架构: %s" % current_key)
        current_action.triggered.connect(
            lambda checked=False, cat=current_key: self._show_syntax_help(cat)
        )

        menu.addSeparator()
        for category in ("x86/x64", "ARM/Thumb", "AArch64", "MIPS"):
            action = menu.addAction(category)
            action.triggered.connect(lambda checked=False, cat=category: self._show_syntax_help(cat))
        return menu

    def _show_syntax_help(self, category):
        """Open the syntax help dialog for the selected architecture."""
        SyntaxHelpDialog(category, self.dialog).exec()

    def _build_register_menu(self):
        """Create the register reference dropdown menu."""
        _, _, QtWidgets = _load_qt()
        menu = QtWidgets.QMenu(self.dialog)

        current_key = _processor_key()
        current_action = menu.addAction("当前架构: %s" % current_key)
        current_action.triggered.connect(
            lambda checked=False, cat=current_key: self._show_register_help(cat)
        )

        menu.addSeparator()
        for category in ("x86/x64", "ARM/Thumb", "AArch64", "MIPS"):
            action = menu.addAction(category)
            action.triggered.connect(lambda checked=False, cat=category: self._show_register_help(cat))
        return menu

    def _show_register_help(self, category):
        """Open the register help dialog for the selected architecture."""
        RegisterHelpDialog(category, self.dialog).exec()

    def _on_text_changed(self):
        """Reset preview state when editor content changes."""
        current_text = self.editor.toPlainText().strip()
        if current_text == self.original_asm_text:
            self.preview_text = self.original_asm_text
            self.preview_bytes = self.original_bytes
            self.preview_infos = _build_preview_infos_from_entries(self.original_entries)
        elif current_text != self.preview_text:
            self.preview_bytes = None
            self.preview_infos = None
        if current_text:
            self.status.setText("编辑中。点击“预览机器码”或直接“应用”。")
        else:
            self.status.setText("当前未输入汇编。")
        self._refresh_context_panel()

    def _preview_machine_code(self):
        """Assemble current editor text and refresh preview/status output."""
        text = self.editor.toPlainText().strip()
        if not text:
            self.status.setText("当前未输入汇编。")
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self._refresh_context_panel()
            return

        try:
            self.preview_bytes, notes, self.preview_infos = _assemble_multiline(
                self.start_ea, text, self.arch_key, self.original_entries
            )
            self.preview_text = text
            self.status.setText(
                "预览成功: %d bytes / 当前范围: %d bytes"
                % (len(self.preview_bytes), self.region_size)
            )
        except Exception as exc:
            self.preview_text = ""
            self.preview_bytes = None
            self.preview_infos = None
            self.status.setText("预览失败: %s" % exc)
        self._refresh_context_panel()

    def _refresh_context_panel(self):
        """Refresh the right-side hint panel from current editor/preview state."""
        text = self.editor.toPlainText().strip()
        preview_bytes = self.preview_bytes if text and text == self.preview_text else None
        preview_infos = self.preview_infos if text and text == self.preview_text else None

        self.hint_panel.setPlainText(
            _build_hint_text(
                self.original_entries,
                text,
                preview_bytes,
                preview_infos,
                self.region_size,
                self.has_selection,
                self.start_ea,
                self.arch_key,
            )
        )

    def _apply_patch(self):
        """Assemble current text and write the resulting bytes into IDA."""
        text = self.editor.toPlainText().strip()
        try:
            patch_bytes, _, line_infos = _assemble_multiline(
                self.start_ea, text, self.arch_key, self.original_entries
            )
            if len(patch_bytes) > self.region_size:
                if self.has_selection:
                    raise RuntimeError(
                        "汇编结果为 %d bytes，已超过当前选中范围的 %d bytes。"
                        % (len(patch_bytes), self.region_size)
                    )

                answer = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_NO,
                    "汇编结果为 %d bytes，已超过当前指令的 %d bytes。\n\n"
                    "是否继续覆盖后续字节？"
                    % (len(patch_bytes), self.region_size),
                )
                if answer != ida_kernwin.ASKBTN_YES:
                    return
                self.region_size = len(patch_bytes)

            if len(patch_bytes) < self.region_size:
                patch_bytes += _build_nop_bytes(
                    self.start_ea + len(patch_bytes),
                    self.region_size - len(patch_bytes),
                )

            _patch_bytes_as_code(self.start_ea, patch_bytes)
            self.preview_text = text
            self.preview_bytes = patch_bytes
            self.preview_infos = line_infos
            ida_kernwin.msg(
                "[%s] 已写入 %d bytes 到 0x%X。\n"
                % (PLUGIN_NAME, len(patch_bytes), self.start_ea)
            )
            self.dialog.accept()
        except Exception as exc:
            ida_kernwin.warning("修改汇编失败:\n%s" % exc)

    def exec(self):
        """Show the assemble dialog modally."""
        return self.dialog.exec()


class AssembleActionHandler(ida_kernwin.action_handler_t):
    """Action handler for the '修改汇编' popup command."""

    def activate(self, ctx):
        """Open the assemble dialog."""
        try:
            AssemblePatchDialog(ctx).exec()
        except Exception as exc:
            ida_kernwin.warning("打开 Assemble 窗口失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class NopActionHandler(ida_kernwin.action_handler_t):
    """Action handler for filling the current range with NOP instructions."""

    def activate(self, ctx):
        """Patch selected instructions or current item with NOP bytes."""
        try:
            patched = 0
            for ea, size in _selected_items(ctx):
                nop_bytes = _build_nop_bytes(ea, size)
                _patch_instruction(ea, nop_bytes)
                patched += 1

            ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.msg("[%s] NOP 完成，处理了 %d 个条目。\n" % (PLUGIN_NAME, patched))
        except Exception as exc:
            ida_kernwin.warning("NOP 失败:\n%s" % exc)
        return 1

    def update(self, ctx):
        """Enable the action only inside the disassembly view."""
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class PopupHooks(ida_kernwin.UI_Hooks):
    """UI hook that injects plugin actions into IDA's disassembly popup menu."""

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        """Attach custom actions when the popup belongs to a disassembly widget."""
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            ACTION_ASSEMBLE,
            None,
            ida_kernwin.SETMENU_APP | ida_kernwin.SETMENU_ENSURE_SEP,
        )
        ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NOP)


class AsmPatchPopupPlugin(ida_idaapi.plugin_t):
    """IDA plugin entry object responsible for action registration and hooks."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Adds Assemble and NOP actions to disassembly right-click menu."
    help = "Right-click in the disassembly view to patch instructions."
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        """Initialize plugin-owned UI hook state."""
        super().__init__()
        self.hooks = None

    def init(self):
        """Register actions and start popup hook injection."""
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_ASSEMBLE,
                "修改汇编",
                AssembleActionHandler(),
                None,
                "调用 IDA 自带的 Assemble 补丁功能",
            )
        )
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_NOP,
                "NOP",
                NopActionHandler(),
                None,
                "将当前指令或选中范围填充为 NOP",
            )
        )

        self.hooks = PopupHooks()
        self.hooks.hook()
        ida_kernwin.msg("[%s] 已加载。\n" % PLUGIN_NAME)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Support IDA's direct plugin run entry point."""
        ida_kernwin.info("右键反汇编窗口即可看到“修改汇编”和“NOP”。")

    def term(self):
        """Unhook UI state and unregister actions on plugin unload."""
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        ida_kernwin.unregister_action(ACTION_ASSEMBLE)
        ida_kernwin.unregister_action(ACTION_NOP)


def PLUGIN_ENTRY():
    """Standard IDA plugin entry point."""
    return AsmPatchPopupPlugin()
