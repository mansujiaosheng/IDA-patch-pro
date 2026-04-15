# ida_patch_pro
目前只测试了9.2pro版本

`ida_patch_pro` 是一个给 IDA Pro 使用的汇编补丁插件。它会在反汇编窗口的右键菜单里增加 `修改汇编`、`代码注入`、`NOP` 和 `补丁回撤列表` 等功能，并提供更适合实际补丁工作的增强界面。

插件当前主要解决这几类问题：

- 直接在右键菜单里修改当前指令或选中范围
- 直接在右键菜单里做 trampoline / code cave 注入
- 对插件自己写入过的补丁做事务级回撤，并可从列表中手动选择
- 预览修改后的机器码和长度变化
- 对多行汇编一起修改
- 自动识别并提示常见助记符、寄存器用途、模板建议
- 自动处理 IDA 展示用的栈变量表达式
- 在 x86/x64 下对 IDA 自带 assembler 不稳定的场景提供 Keystone 兼容汇编兜底

## 功能

- 右键菜单新增 `修改汇编`
- 右键菜单新增 `代码注入`
- 右键菜单新增 `NOP`
- 右键菜单新增 `补丁回撤列表`
- 右键菜单新增 `快捷键设置`
- 支持当前指令和选中范围补丁
- 支持多行汇编编辑
- 支持机器码预览
- 支持语法速查窗口
- 支持寄存器速查表
- 支持寄存器作用提示
- 支持常见指令模板建议
- 支持长度超出时提示将覆盖到哪里
- 支持自动补 NOP
- 支持对 `mov [rsp+198h+var_158], 1` 这类写法做栈变量偏移折算
- 支持 CE 风格 trampoline 编辑
- 支持把补丁同步写回输入文件
- 支持按列表选择任意一条插件补丁事务回撤
- 支持给插件动作设置并保存自定义快捷键

## 截图

### 1. 右键菜单

![Right Click Menu](docs/images/context-menu.png)


### 2. Assemble 主界面

![Assemble Dialog](docs/images/assemble-dialog.png)


### 3. 语法帮助窗口

![Syntax Help](docs/images/syntax-help.png)


### 4. 寄存器速查表

![Register Help](docs/images/register-help.png)

### 5.代码注入

![Code Injection](docs/images/code-injection.png)

### 6.回撤列表
![Revert List](docs/images/revert-list.png)



## 文件说明

- [ida_patch_pro.py](./ida_patch_pro.py)：IDA 插件入口壳文件。IDA 通过它发现插件。
- [ida_patch_pro_pkg](./ida_patch_pro_pkg)：插件目录。实际代码都在这个目录里。
- [ida_patch_pro_pkg/core.py](./ida_patch_pro_pkg/core.py)：插件核心逻辑。包含汇编兼容、普通补丁、代码注入、文件写回、回撤动作、UI 交互。
- [ida_patch_pro_pkg/data.py](./ida_patch_pro_pkg/data.py)：静态提示数据。包含助记符说明、寄存器说明、语法速查表、寄存器速查表。
- `docs/images/`：README 截图目录

### 推荐阅读顺序

如果后续要继续改功能，建议先看这几个文件：

1. [ida_patch_pro.py](./ida_patch_pro.py)
   只负责把 IDA 入口转发到包目录，先确认加载方式。
2. [ida_patch_pro_pkg/core.py](./ida_patch_pro_pkg/core.py)
   真正的功能实现都在这里。大多数行为改动都只需要读这个文件。
3. [ida_patch_pro_pkg/data.py](./ida_patch_pro_pkg/data.py)
   只在你要改右侧提示、语法帮助、寄存器帮助时再读。

### 运行时生成文件

- `plugins\ida_patch_pro_pkg\ida_patch_pro.test.log`：本地测试日志，定位汇编失败、文件写回、trampoline 分配、异常堆栈。
- `plugins\ida_patch_pro_pkg\ida_patch_pro.history.json`：插件补丁历史。`补丁回撤列表` 依赖它来恢复之前写入的字节。
- `plugins\ida_patch_pro_pkg\ida_patch_pro.settings.json`：插件本地设置。当前用于保存动作快捷键。

## 安装方法


1. 把下面两个对象一起复制到 IDA 的 `plugins` 目录：
   - [ida_patch_pro.py](./ida_patch_pro.py)
   - 整个 [ida_patch_pro_pkg](./ida_patch_pro_pkg) 文件夹
2. 重启 IDA。
3. 在反汇编窗口右键，即可看到 `修改汇编`、`代码注入`、`NOP`、`补丁回撤列表` 和 `快捷键设置`。

典型路径示例：

```text
D:\TOOL\ida_9.2\plugins\ida_patch_pro.py
```


## 使用方法

### 修改汇编

1. 在 IDA 反汇编窗口选中一条或多条指令。
2. 右键点击 `修改汇编`。
3. 在弹出的 `Assemble` 窗口中修改汇编文本。
4. 点击 `预览机器码` 查看结果。
5. 点击 `应用` 写入补丁。

### NOP

1. 在反汇编窗口选中一条或多条指令。
2. 右键点击 `NOP`。
3. 插件会将当前指令或选中范围自动填充为 `NOP`。

### 代码注入

1. 在反汇编窗口选中一条或多条要被 trampoline 覆盖的指令。
2. 右键点击 `代码注入`。
3. 编辑框会默认载入当前所选汇编，你可以直接改、删、插、重排。
4. 需要真实运行/调试时，勾选 `同时写入输入文件`。
5. 点击 `预览代码注入` 或 `应用`。

### 补丁回撤列表

1. 把光标停在你刚改过的地址附近，或选中对应区域。
2. 右键点击 `补丁回撤列表`。
3. 插件会列出已记录的补丁事务，你可以手动选择任意一条回撤。

### 快捷键设置

1. 在反汇编窗口右键点击 `快捷键设置`，或直接运行插件入口。
2. 为各动作输入你想要的快捷键，留空表示取消该动作快捷键。
3. 点击 `保存` 后，插件会保存到本地设置文件，并尽量立即更新当前 IDA 会话。

当前默认快捷键：

- `修改汇编`：`Ctrl+Alt+A`
- `代码注入`：`Ctrl+Alt+T`
- `NOP`：`Ctrl+Alt+N`
- `补丁回撤列表`：`Ctrl+Alt+R`

## 界面说明

`Assemble` 窗口主要分成两部分：

- 左侧：汇编编辑区
- 右侧：上下文提示区

右侧提示区会展示：

- 原指令
- 原机器码
- 当前编辑内容
- 新机器码预览
- 兼容说明
- 指令说明
- 寄存器提示
- 模板建议

顶部 `语法` 按钮可打开当前架构的常见汇编语法帮助表。

顶部 `寄存器` 按钮可打开当前架构的寄存器速查表，并支持关键字过滤。

## 兼容性

- 已针对 IDA Pro 9.2 使用场景调整
- UI 依赖 IDA 自带的 PySide6
- x86/x64 下支持 Keystone 兼容汇编兜底

如果 IDA 自带 assembler 无法处理某些简单改写，插件会自动尝试更稳的兼容路径。

## 常见场景

### 1. 改寄存器赋值

```asm
mov rdi, rbp
```

可以改成：

```asm
mov edi, 1
```

或：

```asm
xor edi, edi
```

### 2. 改栈变量写入

原始显示可能是：

```asm
mov     [rsp+198h+var_158], eax
```

编辑时可以直接输入：

```asm
mov dword ptr [rsp+198h+var_158], 1
```

插件会自动把 IDA 展示用的栈变量表达式折算成真实可汇编偏移再尝试汇编。

### 3. 覆盖多条指令

如果新机器码长度大于当前单条指令长度，插件会提示你是否继续覆盖后续字节。

## 注意事项

- 修改汇编前建议先备份数据库
- 新机器码长度变长时，可能覆盖后续指令
- 某些向量指令不能直接写立即数，右侧模板建议会给出替代写法
- 如果你修改的是选中范围，写入长度不能超过该选区
