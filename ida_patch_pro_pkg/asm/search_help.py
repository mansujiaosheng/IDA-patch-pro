"""Reusable help text for assembly-pattern search."""

from .operands import sanitize_asm_line, split_operands
from .search import SEARCH_MODE_EXACT, SEARCH_MODE_TEXT

_ZERO_OPERAND_MNEMONICS = {
    "aaa",
    "aad",
    "aam",
    "aas",
    "cbw",
    "cdq",
    "cdqe",
    "clc",
    "cld",
    "cli",
    "cmc",
    "cpuid",
    "cqo",
    "cwd",
    "cwde",
    "hlt",
    "int3",
    "iret",
    "iretd",
    "iretq",
    "lahf",
    "leave",
    "mfence",
    "nop",
    "pause",
    "popf",
    "popfd",
    "popfq",
    "pushf",
    "pushfd",
    "pushfq",
    "rdtsc",
    "ret",
    "retn",
    "sahf",
    "sfence",
    "stc",
    "std",
    "sti",
    "syscall",
    "sysenter",
    "ud2",
}


def _looks_like_mnemonic_only(line):
    """Return whether one search line is likely just a mnemonic without operands."""
    mnem, operands = split_operands(line)
    if not mnem:
        return False
    if operands:
        return False
    return mnem.lower() not in _ZERO_OPERAND_MNEMONICS


def build_search_usage_text(query_text, mode=SEARCH_MODE_EXACT):
    """Build right-panel usage notes and examples for assembly search."""
    mode = (mode or SEARCH_MODE_EXACT).strip().lower()
    lines = [sanitize_asm_line(line) for line in (query_text or "").splitlines()]
    lines = [line for line in lines if line]
    mnemonic_only = any(_looks_like_mnemonic_only(line) for line in lines)

    if mode == SEARCH_MODE_TEXT:
        text = [
            "搜索写法:",
            "- 当前模式支持按助记符、寄存器或文本关键字搜索。",
            "- `cmp` 可以搜所有助记符为 `cmp` 的指令。",
            "- `eax` 可以搜所有出现 `eax` 的指令。",
            "- `printf`、`var_8`、`[rbp+var_8]` 这类文本也可以直接搜。",
            "- 多行搜索表示“连续多条指令逐行文本匹配”。",
            "",
            "示例:",
            "- `cmp`：搜索所有比较指令。",
            "- `eax`：搜索所有涉及 `eax` 的指令。",
            "- `cmp eax, ebx`：搜索文本上包含这条完整指令的地方。",
            "- `cmp` 换行 `jz`：搜索连续出现的 `cmp` / `jz` 两条指令。",
        ]
        if mnemonic_only:
            text.extend(
                [
                    "",
                    "当前输入提示:",
                    "- 你现在的输入就是这类模式的典型用法，可以直接搜索。",
                ]
            )
        return "\n".join(text)

    text = [
        "搜索写法:",
        "- 大多数情况下要输入完整指令，而不是只写助记符。",
        "- `cmp` 不表示“搜索所有 cmp 指令”；它只是一个不完整的汇编文本。",
        "- 应写成 `cmp eax, ebx`、`mov [rbp+var_8], 0Bh` 这类完整形式。",
        "- `nop`、`ret` 这类零操作数指令可以直接只写一个单词。",
        "- 多行搜索表示“连续多条指令整体匹配”。",
        "",
        "匹配语义:",
        "- 插件会在每个候选指令头重新汇编你的输入，再和当前位置实际字节比较。",
        "- 这意味着它搜索的是“编码后完全一致”的模式，不是“助记符模糊搜索”。",
        "- 地址相关写法会按候选地址重新计算，例如 `jmp label`、`call printf`、`lea rax, symbol`。",
        "",
        "示例:",
        "- `cmp eax, ebx`：搜索这条完整比较指令。",
        "- `nop`：搜索单条 NOP。",
        "- `mov [rbp+var_8], 0Bh`：搜索包含 IDA 栈变量显示写法的指令。",
        "- `cmp eax, ebx` 换行 `jz loc_140001234`：按两条连续指令一起搜索。",
        "- `call printf`：按符号参与汇编后的真实编码搜索。",
    ]
    if mnemonic_only:
        text.extend(
            [
                "",
                "当前输入提示:",
                "- 你现在的输入看起来像“只写了助记符”。",
                "- 如果你想找所有比较指令，请切到“助记符/寄存器/文本”模式后直接搜 `cmp`。",
                "- 如果你想找特定比较指令，请继续使用当前模式并写成 `cmp eax, ebx`。",
            ]
        )
    return "\n".join(text)
