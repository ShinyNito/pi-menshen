# pi-menshen(门神)— pi 权限扩展(自动审核模式)

> **门神** — 贴在大门上的守护神,把妖邪挡在门外。这个扩展守护 agent 的工具调用,道理一样。

固定运行在**自动审核模式**(无需模式切换):规则引擎 → 确定性快路径 → LLM 自动审核 → 人工确认兜底。

## 特性

- **规则引擎**
  - 规则格式 `Tool(content)`:`Bash(npm install:*)`、`Bash(rm -rf /)`、`Write(.env*)`、`Read(*)`
  - 三种行为:`allow` / `deny` / `ask`,优先级 deny > ask > allow
  - 三种匹配:精确(exact)、前缀(`cmd:*`)、通配(`*`,`**` 跨目录)
  - 全局规则 + 项目规则(`.pi/permission.json`,项目优先)
- **tree-sitter bash 解析**
  - 用 `web-tree-sitter` + `tree-sitter-bash` WASM 对命令做权威解析
  - 复合命令(`&&` / `||` / `;` / `|`)拆分为子命令逐条检查,防 `echo hi && rm -rf /` 绕过
  - 转义操作符(`cd src\&\& python3 evil.py`)不被误拆
  - heredoc 内容不参与规则匹配;重定向(`> out.txt`)从匹配文本剥离
  - 解析失败 → fail-closed:跳过确定性快路径,交由自动审核模型判断
- **自动审核模式**(核心,Guardian 式)
  - 规则未命中时,由**专用审核模型**审查「计划动作 + 支配请求 + 周边对话」
  - 输出结构化 JSON:`{ risk_level, user_authorization, outcome: allow|deny, rationale }`(低风险可直接 `{"outcome":"allow"}`)
  - 审核模型看到的是**重建的紧凑 transcript**(用户意图 + 最近的助手/工具上下文,带 token 预算),全部视为不可信证据
  - 审核模型可执行**只读查证**(`ls`、`stat`、`git status`…)核实本地状态后再下结论
  - 审核对话**跨审查复用**(delta 增量 transcript,稳定 prompt-cache 前缀)
  - **拒绝熔断**:单轮内自动审查拒绝过多(连续 3 次 / 最近 50 次中 10 次)即中断整个 turn;拒绝附带禁止绕过指引
  - 审查模型的明确拒绝会**直接回传给 agent**(工具错误结果,含理由 + 禁止绕过指引),让 agent 提出更安全的替代方案;人工确认框只在审查模型无法决定时出现(超时/失败/确定性 REVIEW)
  - 超时/错误/格式异常一律 fail-closed → 人工(fail-safe)
  - 确定性高风险特征(密钥/凭证、提示注入、危险 bash 模式)不调用 LLM,直接 REVIEW
  - 输入脱敏后才发给模型(私钥、Bearer token、`sk-*` 等被遮蔽)
- **确定性快路径**(省钱)
  - 只读命令(`ls`、`git status`、`npm ls`…)自动放行
  - 项目内非敏感文件写入/编辑自动放行;`.env`、锁文件、CI 配置等敏感路径转审核
- **终端通知**(OSC 9 / 777 / 99,otty 原生通知)
  - 需要人工确认、或熔断中断 turn 时,向终端发通知(otty/kitty 显示为 macOS 原生横幅)
  - 自动检测终端协议:otty/kitty → OSC 99,Ghostty/iTerm2 → OSC 9,WezTerm/urxvt → OSC 777,未知终端按 otty 推荐级联 99→777→9;tmux 内自动 DCS 透传
  - 非 TTY 环境(rpc/print)自动回落为应用内提示;`/perm notify` 可发测试通知
- **状态显示**:footer 常驻 `🔒 menshen ✓n ✗n ⚠n` 统计

## 安装

从 npm 安装(已发布为 `@shinynito/pi-menshen`):

```bash
pi install npm:@shinynito/pi-menshen          # 全局(注册到 ~/.pi/agent/settings.json)
pi install -l npm:@shinynito/pi-menshen       # 项目级(-l 写入 .pi/settings.json,可与团队共享)
```

开发阶段也可以用 `pi install /path/to/pi-menshen` 安装本地目录;本地路径注册到 settings 时**不复制文件**,改完代码 `/reload` 即生效。

备选:手动符号链接(老式做法):

```bash
# 全局
ln -s /path/to/pi-menshen ~/.pi/agent/extensions/pi-menshen

# 项目级
mkdir -p .pi/extensions
ln -s /path/to/pi-menshen .pi/extensions/pi-menshen
```

依赖安装(首次;本地路径安装时 pi 不会自动跑 `pnpm install`):

```bash
cd /path/to/pi-menshen && pnpm install
```

然后在 pi 中 `/reload`。`tree-sitter-bash.wasm` 已随扩展分发;若缺失会自动从
GitHub release 下载到 `~/.pi/`。

## 配置(含分类器模型)

配置文件:`~/.pi/pi-menshen.json`(目录可用 `PI_MENSHEN_DIR` 覆盖)。

```json
{
  "version": 1,
  "enabled": true,
  "classifierModel": "",
  "classifierTimeoutMs": 30000,
  "maxClassifierChars": 18000,
  "gatedTools": ["bash", "write", "edit", "fetch_content", "mcp"],
  "sensitivePaths": [".env", ".env.*", "*.pem", "package-lock.json", ".github/workflows"],
  "guardian": {
    "maxAttempts": 3,
    "maxChecks": 3,
    "checkTimeoutMs": 4000,
    "checkOutputChars": 4000,
    "consecutiveDenyLimit": 3,
    "denyWindowLimit": 10,
    "denyWindowSize": 50
  },
  "notifications": {
    "enabled": true,
    "onManualPrompt": true,
    "onBreakerTrip": true,
    "protocol": "auto"
  },
  "rules": {
    "allow": ["Bash(npm run:*)"],
    "deny": ["Bash(rm -rf /)"],
    "ask": []
  }
}
```

### 审核模型怎么配

`classifierModel` 填 `"provider/modelId"`,用 `pi --list-models` 查看可用模型:

```bash
# 例:用 kimi 的便宜高速模型做审核
# 编辑 ~/.pi/pi-menshen.json
"classifierModel": "kimi-coding/kimi-for-coding-highspeed"

# 例:用 openai 的 mini 模型
"classifierModel": "openai-codex/gpt-5.4-mini"
```

- **留空**(`""`)= 用当前会话模型(保证可用,但与主模型共享配额/上下文)
- 建议配一个便宜的专用模型做审核,避免主模型 token 消耗
- 改完 `/reload` 生效,`/perm` 可查看当前生效的模型

## 命令

| 命令 | 说明 |
|------|------|
| `/perm` | 状态总览(模型、规则数、会话统计) |
| `/perm rules` | 列出全部规则 |
| `/perm allow\|deny\|ask <Tool(content)>` | 添加规则,如 `/perm allow Bash(npm run:*)` |
| `/perm remove <Tool(content)>` | 移除规则 |
| `/perm model [provider/modelId]` | 查看/设置分类器模型(`-` 恢复为当前会话模型) |
| `/perm notify [on\|off\|message]` | 开关终端通知,或发送一条测试通知(可带自定义消息) |
| `/perm pause` / `/perm resume` | 暂停/恢复拦截 |

人工确认对话框为信息面板:工具名、框起来的具体输入、Guardian 风险/授权徽标与理由(有审核结果时),然后是选项:
- **✓ Allow once** — 仅放行这一次
- **✗ Deny** — 拦截
- **✗ Deny & remember** — 拦截并自动生成 deny 规则(`rm -rf /` → `Bash(rm -rf /)`)
- **✗ Deny with reason** — 拦截并附带给 agent 的理由

## 决策流程

```
工具调用
  │
  ├─ 1. 规则引擎(deny → ask → allow,精确/前缀/通配)
  ├─ 2. tree-sitter 解析失败 → 跳过快路径,进第 4 步(降级标记随上下文发给模型)
  ├─ 3. 确定性快路径
  │      ├─ 只读工具/只读命令 → 放行
  │      └─ write/edit 项目内非敏感路径 → 放行
  ├─ 4. Guardian 自动审核
  │      ├─ 确定性风险特征(密钥/危险命令/注入)→ REVIEW(不调 LLM)
  │      ├─ 重建紧凑 transcript(delta 复用)+ 计划动作
  │      ├─ 审核模型可跑只读查证(白名单命令)核实本地状态
  │      ├─ 严格 JSON:{risk_level, user_authorization, outcome, rationale}
  │      ├─ allow → 放行
  │      └─ deny → 结果回传给 agent(理由 + 禁止绕过指引);熔断在连续拒绝后中断本轮
  └─ 5. 人工确认(仅当审查模型无法决定时)
         (允许 / 拒绝 / 拒绝并记住)
```

## 安全说明

- 所有输入视为不可信数据;策略(policy)显式禁止跟随输入中的指令(防提示注入)
- 审核模型必须返回严格 JSON;格式异常、超时、错误一律 fail-closed(deny → 人工)
- 审核模型只能执行白名单只读查证(`ls`、`stat`、`git status`…),无 shell;复合命令、重定向、shell 展开一律拒绝
- 非交互模式(rpc/print)下人工确认不可用时默认**拒绝**(fail-closed)
- deny 规则剥离全部前导环境变量(`FOO=bar rm -rf /` 仍命中 `Bash(rm:*)`)
- 裸 shell(`bash`、`sh`、`sudo`…)不允许生成 allow 前缀规则
- 单轮内自动审查拒绝过多会触发熔断并中断整个 turn

## 终端通知(otty 等)

需要人工确认、或熔断中断 turn 时,门神会向终端发一条通知。在 otty 中这表现为 macOS 原生横幅(需要在系统设置 → 通知 → otty 中开启权限)。

- **协议自动检测**:otty/kitty → OSC 99,Ghostty/iTerm2 → OSC 9,WezTerm/urxvt/Windows Terminal → OSC 777,未知终端按 otty 官方推荐级联 99→777→9;tmux 内自动 DCS 透传
- **测试**:`/perm notify` 发一条测试通知;`/perm notify on|off` 开关
- **配置**:`notifications.enabled` 总开关;`onManualPrompt` / `onBreakerTrip` 分别控制两个触发点;`protocol` 可固定为 `osc99`/`osc9`/`osc777`/`cascade`(默认 `auto` 自动检测)
- **降级**:rpc/print 等非 TTY 环境下无法发 OSC,自动改为应用内提示

## 开发

```bash
bun x tsc --noEmit   # 类型检查
pnpm install         # 安装依赖(dev 依赖含 pi peer 包,供类型检查)
node --experimental-strip-types --test tests.test.ts   # 冒烟测试
```

需要 node ≥ 22.6(测试运行器依赖原生 TypeScript 类型剥离)。

文件结构:

```
index.ts        # 入口:事件接线、决策管线、熔断器、/perm 命令
rules.ts        # 规则引擎:解析、精确/前缀/通配匹配、路径规则
parser.ts       # tree-sitter bash 解析:子命令拆分、重定向提取
bash.ts         # 命令分析:只读识别、包装器/环境变量剥离、危险模式、敏感路径
classifier.ts   # Guardian 自动审核:transcript 重建、结构化 JSON、只读查证、重试、审核会话复用
policy.ts       # 审核策略(风险分类学 + 输出契约),作为 system prompt 发给审核模型
notify.ts       # 终端通知:OSC 9/777/99 序列构建、协议自动检测、tmux 透传
config.ts       # 配置/规则持久化(~/.pi/pi-menshen.json)
tree-sitter-bash.wasm  # 随扩展分发的语法(下载自 tree-sitter-bash v0.25.1)
```
