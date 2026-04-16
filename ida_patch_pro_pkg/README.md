# ida_patch_pro_pkg

这份文档只描述包内代码结构，目标是让后续继续开发时能快速知道：

- 每个文件负责什么
- 关键函数/类在哪
- 修改某类问题时应该优先进哪个模块

## 总体分层

- `plugin.py`
  负责插件生命周期，不写业务逻辑。
- `actions.py`
  负责动作注册、右键菜单、顶部菜单、打开窗口。
- `ui/`
  负责各个窗口和用户交互。
- `asm/`
  负责汇编文本解析、兼容改写、汇编兜底、汇编搜索、右侧提示。
- `patching/`
  负责选区、范围规划、普通补丁写入、Fill Range、事务、历史、回撤。
- `trampoline/`
  负责代码注入规划、代码洞分配、函数尾块挂接。
- `backends/`
  负责文件写回、PE 节操作、EA 与文件偏移映射。
- `runtime/`
  负责运行时路径。
- `constants.py` / `logging_utils.py` / `data.py`
  负责常量、日志、静态帮助数据。

## 顶层文件

### `__init__.py`

主要职责：
- 包入口。
- 热重载时重新导入 `plugin.py`。

关键函数：
- `_reload_or_import()`
- `PLUGIN_ENTRY()`

### `plugin.py`

主要职责：
- 定义 IDA 插件对象。
- 在 `init/run/term` 中串起动作注册和 UI hook。

关键类 / 函数：
- `IdaPatchProPlugin`
- `PLUGIN_ENTRY()`

适合放这里的改动：
- 插件加载/卸载行为
- 入口行为
- 直接运行插件时默认打开哪个窗口

### `actions.py`

主要职责：
- 注册 action。
- 注入右键菜单和顶部菜单。
- 把动作分发到具体对话框或补丁逻辑。

关键函数：
- `attach_main_menu_actions()`
- `detach_main_menu_actions()`
- `register_actions()`
- `unregister_actions()`

关键类：
- `AssembleActionHandler`
- `TrampolineActionHandler`
- `NopActionHandler`
- `FillRangeActionHandler`
- `SearchActionHandler`
- `RollbackActionHandler`
- `ShortcutSettingsActionHandler`
- `PopupHooks`

适合放这里的改动：
- 新增一个动作
- 调整菜单入口
- 修改右键菜单顺序
- 修改某个动作打开的窗口

### `core.py`

主要职责：
- 兼容薄壳。
- 保留旧入口导向 `plugin.py`。

说明：
- 不要再把新逻辑塞回这个文件。

### `constants.py`

主要职责：
- 放动作 ID、菜单名、段名、默认文件名、默认快捷键等固定常量。

适合放这里的改动：
- 改 action id
- 改 `.patch` / `.patchf` 命名
- 改默认快捷键

### `logging_utils.py`

主要职责：
- 统一写测试日志。
- 统一异常日志格式。
- 生成 `trace_id`。

关键函数：
- `debug_log()`
- `debug_log_exception()`
- `make_trace_id()`
- `format_bytes_hex()`

### `ida_adapter.py`

主要职责：
- 对常用 IDA API 做兼容封装。
- 集中处理 imagebase、位数、segment 查询、文件路径等版本差异。

关键函数：
- `input_file_path()`
- `find_segment_by_name()`
- `read_idb_bytes()`
- `current_imagebase()`
- `is_64bit_database()`
- `segment_bitness_code()`
- `rebase_history_ea()`

适合放这里的改动：
- 兼容 IDA 版本差异
- 兼容某个 API 在 9.2 下的变化

### `data.py`

主要职责：
- 静态帮助数据。
- 助记符解释、寄存器说明、语法表、寄存器表。

关键函数：
- `_register_hint()`

## `ui/`

### `ui/common.py`

主要职责：
- 统一加载 PySide6。
- 统一管理非模态窗口生命周期。

关键函数：
- `load_qt()`
- `show_modeless_dialog()`

### `ui/assemble_dialog.py`

主要职责：
- 普通“修改汇编”窗口。
- 管理编辑、预览、应用、长度检查、右侧提示区。

关键类：
- `AssemblePatchDialog`

这个文件里最重要的行为：
- 打开时读取当前选区原始汇编
- 手动/实时预览机器码
- 单条指令场景按完整指令边界扩展补丁范围
- 汇编超长时按本地策略决定“继续覆盖 / 改用代码注入 / 每次询问”
- 应用补丁事务
- 需要时自动补 NOP

### `ui/trampoline_dialog.py`

主要职责：
- “代码注入 / trampoline”窗口。
- 管理代码洞主体编辑、预览、风险确认、实际应用。

关键类：
- `TrampolinePatchDialog`

这个文件里最重要的行为：
- 默认载入当前选中的原始汇编
- 支持 `include_original`
- 支持实时预览代码洞逐行机器码
- 支持直接打开语法帮助表和寄存器帮助表
- 支持仅 IDB 和写回输入文件两种模式
- 写回输入文件时按格式选择策略：PE/DLL/PYD 走 `.patchf`，ELF/SO 自动扩展最后一个 `PT_LOAD`
- 实际落盘前重新确认代码洞位置

### `ui/rollback_dialog.py`

主要职责：
- 展示补丁历史列表。
- 允许手工选择事务回撤。
- 允许单条删除、批量勾选删除和清空历史记录。

关键类：
- `RollbackHistoryDialog`

### `ui/fill_range_dialog.py`

主要职责：
- `Fill Range` 窗口。
- 读取起止地址、汇编文本和尾部补齐模式。
- 调用独立的 Fill Range 预览/应用服务。

关键类：
- `FillRangeDialog`

### `ui/search_dialog.py`

主要职责：
- `汇编搜索` 窗口。
- 收集搜索范围和汇编文本。
- 展示搜索命中结果并支持双击跳转。
- 管理搜索历史、结果快照恢复和批量删除。
- 提供搜索窗口内的语法帮助表和寄存器帮助表入口。
- 在右侧持续展示“完整指令写法”和搜索例子。

关键类：
- `AssemblySearchDialog`

### `ui/shortcut_dialog.py`

主要职责：
- 快捷键设置窗口。
- 保存本地设置并尽量立即应用到当前会话。

关键类：
- `ShortcutSettingsDialog`

### `ui/reference_dialogs.py`

主要职责：
- 语法帮助表和寄存器帮助表。
- 通用表格过滤 UI。

关键类：
- `ReferenceTableDialog`
- `SyntaxHelpDialog`
- `RegisterHelpDialog`

## `asm/`

### `asm/assemble.py`

主要职责：
- 真正执行汇编。
- IDA assembler 和 Keystone 两条路径。
- 多行汇编拼接。

关键函数：
- `try_assemble_line()`
- `try_assemble_line_keystone()`
- `assemble_bytes()`
- `assemble_multiline()`

### `asm/rewrite.py`

主要职责：
- 汇编兼容改写。
- 符号解析、分支目标解析、RIP 相对改写。
- 为 IDA assembler / Keystone 失败场景生成兼容候选。

关键函数：
- `rewrite_line_for_assembly()`
- `resolve_symbol_operand_ea()`
- `resolve_branch_symbol_operand_ea()`
- `assemble_direct_branch_bytes()`
- `fallback_assembly_candidates()`

这个文件里最近需要特别注意的行为：
- `lea reg, symbol` 在 x64 文件补丁场景下会优先改成 RIP 相对寻址，避免 ASLR 下失效。
- `call/jmp symbol` 在 trampoline 里会优先解析到可执行代码入口，而不是 GOT / 数据别名；例如 ELF 下的 `_printf` 会优先落到 `.printf` / `printf@plt` 风格入口。

说明：
- 如果某条指令“能写但汇编失败”，优先从这里下断点/加日志。

### `asm/search.py`

主要职责：
- 按汇编模式搜索当前数据库。
- 从每个候选指令头重新汇编查询文本，再比较实际字节。

关键函数：
- `search_assembly()`

### `asm/search_help.py`

主要职责：
- 生成 `汇编搜索` 右侧的使用说明和例子文本。
- 明确区分“完整指令搜索”和“仅助记符”的差别。

关键函数：
- `build_search_usage_text()`

### `asm/rewrite.py`

主要职责：
- 汇编前兼容改写。
- 栈变量展示名转真实可汇编操作数。
- 内存立即数自动补 `size ptr`。
- 普通符号立即数、`[symbol]` 内存操作数、`call/jmp symbol`、`lea reg, symbol` 兼容改写。

关键函数：
- `rewrite_line_for_assembly()`
- `infer_memory_size_keyword()`
- `resolve_symbol_operand_ea()`
- `resolve_memory_symbol_target_ea()`
- `assemble_direct_branch_bytes()`
- `fallback_assembly_candidates()`

说明：
- “IDA 里显示能看懂，但 assembler 不接受”的问题，大多应该改这里。

### `asm/operands.py`

主要职责：
- 操作数解析与归一化。
- 助记符提取、寄存器提取、立即数解析。
- 栈变量展示名重建。
- `...h` 立即数字面量规范化。

关键函数：
- `split_operands()`
- `parse_immediate_value()`
- `normalize_hex_suffix_literals()`
- `rebuild_stack_operand_text()`
- `build_operand_infos()`
- `processor_key()`

### `asm/hints.py`

主要职责：
- 右侧提示区文案。
- 指令说明、模板建议、长度提示。

关键函数：
- `mnemonic_hint_text()`
- `build_template_suggestions()`
- `length_warning_text()`
- `build_hint_text()`

## `patching/`

### `patching/selection.py`

主要职责：
- 读取当前地址、当前选区、hook 区域。
- 读取原始指令文本、原始字节、原始 operand info。

关键函数：
- `current_ea()`
- `selected_items()`
- `patch_region()`
- `hook_region()`
- `build_entry_for_ea()`
- `get_original_entries()`
- `get_entries_for_range()`
- `get_entries_for_line_count()`

### `patching/ranges.py`

主要职责：
- 指令边界扩展。
- 按头遍历范围内的 item。

关键函数：
- `instruction_range_for_size()`
- `iter_instruction_heads()`

### `patching/assemble_plan.py`

主要职责：
- 普通汇编修改的非 UI 预览计划。
- 统一处理汇编结果长度、边界扩展和尾部 NOP。

关键函数：
- `preview_assembly_patch()`

### `patching/bytes_patch.py`

主要职责：
- 实际改字节。
- 自动重建代码。
- 普通补丁和 NOP 写入。

关键函数：
- `build_nop_bytes()`
- `patch_bytes_as_code()`
- `apply_code_patch()`

### `patching/fill.py`

主要职责：
- Fill Range 的非 UI 预览与应用。
- 重复汇编当前输入直到填满目标范围。

关键函数：
- `preview_fill_range()`
- `apply_fill_range_plan()`

### `patching/transactions.py`

主要职责：
- 事务开始、记录、提交。
- 捕获 old/new bytes。
- 保存文件写回前后的 chunk 信息。

关键函数：
- `begin_patch_transaction()`
- `record_transaction_operation()`
- `commit_patch_transaction()`
- `capture_patch_operation()`
- `apply_operation_bytes()`
- `resolve_operation_ea()`

说明：
- 只要一个动作能修改字节，就应该先走事务记录，再落盘。

### `patching/history_store.py`

主要职责：
- 设置文件和历史文件的 JSON 读写。
- 快捷键保存和加载。
- 补丁历史的单条删除、批量删除和清空。

关键函数：
- `load_plugin_settings()`
- `save_plugin_settings()`
- `load_action_shortcuts()`
- `save_action_shortcuts()`
- `load_patch_history()`
- `save_patch_history()`
- `delete_patch_history_entry()`
- `delete_patch_history_entries()`
- `clear_patch_history()`

### `patching/search_history.py`

主要职责：
- 汇编搜索历史的持久化。
- 搜索结果快照的序列化/反序列化。
- 按数据库隔离搜索历史。

关键函数：
- `load_search_history()`
- `save_search_history()`
- `remember_search_history()`
- `clear_search_history()`
- `normalize_search_history_entry()`

### `patching/overflow_policy.py`

主要职责：
- 保存普通 `Assemble` 在“汇编超长”场景下的默认处理策略。
- 给 UI 和核心逻辑提供统一的策略枚举。

关键函数：
- `load_oversize_policy()`
- `save_oversize_policy()`

### `patching/rollback.py`

主要职责：
- 正式回撤一个事务。
- 检测 stale 状态。
- 生成回撤列表里显示的状态和描述。

关键函数：
- `rollback_transaction()`
- `rollback_partial_transaction()`
- `find_stale_rolled_back_entry()`
- `describe_history_entry()`
- `entry_runtime_status()`

## `trampoline/`

### `trampoline/planner.py`

主要职责：
- 代码注入预览。
- 生成最终 code cave 文本。
- 风险提示。
- 计算入口 `jmp` 和 code cave 机器码。

关键函数：
- `build_trampoline_lines()`
- `preview_trampoline_plan()`
- `parse_trampoline_orig_marker()`
- `trampoline_risk_notes()`
- `trampoline_custom_risk_notes()`

说明：
- “预览没问题但应用错位”先看 planner，再看 caves。

### `trampoline/hints.py`

主要职责：
- 生成代码注入窗口右侧的说明、机器码预览和高级语法例子。

关键函数：
- `build_trampoline_hint_text()`
- `build_trampoline_example_lines()`

### `trampoline/caves.py`

主要职责：
- IDB 内 `.patch` 段管理。
- 文件内现成 code cave 搜索。
- `.patch` 段下一个可分配地址计算。

关键函数：
- `find_file_code_cave()`
- `find_patch_segment()`
- `next_patch_cursor()`
- `ensure_patch_segment()`
- `preview_patch_segment_allocation()`

### `trampoline/function_attach.py`

主要职责：
- 把 code cave 挂成原函数 tail chunk。
- 回撤时清理 tail chunk / 名称。

关键函数：
- `attach_cave_to_owner_function()`
- `cleanup_trampoline_tail()`

## `backends/`

### `backends/elf_backend.py`

主要职责：
- ELF / SO 写回输入文件时的 `.patchf` 规划与同步。
- 扩展最后一个 `PT_LOAD`，为 trampoline 提供文件内可执行代码洞。

关键函数：
- `elf_patch_segment_info()`
- `create_elf_patch_segment()`
- `extend_elf_patch_segment()`
- `sync_elf_patch_segment_to_idb()`
- `prepare_elf_patch_segment()`

这个文件里最近需要特别注意的行为：
- 当前策略不是把补丁区插到 ELF 文件中间，而是追加到文件尾，再扩展最后一个 `PT_LOAD` 去覆盖这段补丁区。
- 创建 patch 区后，后续同步和实际写入必须继续使用同一块 `.patchf`，不能在“当前 EOF”上重新漂移计算一块新地址，否则会导致文件已写字节和运行时映射范围不一致。
- IDB 里的 `.patchf` 同步现在直接按 `raw_ptr/raw_size` 从输入文件读取字节补进段内容，不再依赖 `file2base()` 成功与否。

### `backends/filemap.py`

主要职责：
- 维护 EA <-> 文件偏移映射。
- 为 `.patchf` 这类文件内补丁段提供回退映射。

这个文件里最近需要特别注意的行为：
- ELF `.patchf` 的映射会优先参考段注释里的 `raw_ptr`。
- 若现有 `.patchf` 映射已经超出当前文件大小，应视为过期状态，不能继续当成有效 patch 区复用。

### `backends/filemap.py`

主要职责：
- EA 到文件偏移的映射。
- 补丁写回时切分连续 chunk。

关键函数：
- `ea_file_offset()`
- `build_file_patch_chunks()`
- `write_patch_chunks_to_input_file()`

### `backends/pe_backend.py`

主要职责：
- 读写输入文件的 PE 节表。
- 管理 `.patchf` 节的创建、扩展、映射回 IDA。

关键函数：
- `pe_patch_section_info()`
- `create_pe_patch_section()`
- `extend_pe_patch_section()`
- `sync_file_patch_segment_to_idb()`
- `prepare_file_patch_segment()`

说明：
- 只要涉及“写回输入文件时的 code cave 存放位置”，优先看这里。

### `backends/base.py`

主要职责：
- 预留 backend 接口基类。

当前状态：
- 现在作用很小，主要是给后续扩展留位。

## `runtime/`

### `runtime/paths.py`

主要职责：
- 统一运行时文件路径。
- 日志、历史、设置文件都从这里取路径。

关键函数：
- `runtime_file_path()`
- `test_log_path()`
- `history_file_path()`
- `settings_file_path()`

## 修改建议

按问题类型，优先改这些位置：

- 菜单、动作、快捷键入口问题：
  `plugin.py`、`actions.py`、`ui/shortcut_dialog.py`
- 普通汇编改写/汇编失败：
  `asm/assemble.py`、`asm/rewrite.py`、`asm/operands.py`
- 右侧提示区文案：
  `asm/hints.py`、`data.py`
- 普通补丁写入/NOP/事务：
  `patching/bytes_patch.py`、`patching/transactions.py`
- 回撤列表和回撤异常：
  `patching/rollback.py`、`ui/rollback_dialog.py`
- 代码注入预览和风险提示：
  `trampoline/planner.py`、`ui/trampoline_dialog.py`
- `.patch` / `.patchf` 分配和文件写回：
  `trampoline/caves.py`、`backends/filemap.py`、`backends/pe_backend.py`
- IDA API 兼容性问题：
  `ida_adapter.py`

## 不建议的做法

- 不要再把新功能堆回 `core.py`。
- 不要在 `ui/` 里直接写文件偏移和 PE 节逻辑。
- 不要在 `actions.py` 里直接堆复杂业务判断，动作层只做分发。
- 不要在 `asm/` 里直接做历史持久化；事务相关统一走 `patching/`。
