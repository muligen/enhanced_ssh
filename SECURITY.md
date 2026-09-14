# Security Model

## 信任边界

Gateway 控制的是“只拥有 IPC/MCP 调用能力的 Agent”。它不是同一 Windows 账户内的强隔离沙箱。如果 Agent 同时拥有任意 shell、进程、文件读写或调试权限，它可以直接运行 `ssh.exe`、读取运行时令牌、修改配置或绕过 daemon。此时必须先用独立 Windows 账户、ACL、容器或虚拟机建立 OS 级隔离。

建议 daemon 使用专用的非管理员 Windows 账户运行，并确保以下内容只有该账户和 `SYSTEM` 可读写：

- `runtime.dataDirectory`
- gateway 配置
- `ssh_config` 和 `known_hosts`
- 全局 SSH 私钥库、各 revision 的私钥副本、证书和 ProxyCommand 依赖的凭据
- gateway 安装目录和原生 supervisor

不要把运行目录放在网络共享或多个用户可写的目录中。

## IPC

Windows Named Pipe 的随机名称本身不是安全边界。daemon 启动时生成 256-bit 随机 token，保存在经 ACL 收紧的 `runtime.json`；连接首帧必须使用恒定时间比较完成认证。未认证连接不能调用任何业务方法。认证握手还严格要求内部协议 v6；版本不一致会 fail closed，不会降级解析新旧方法或 schema。

daemon 使用 data directory 内的原子 lease 保证同一运行目录只有一个实例。启动时会把 data directory、审计目录/文件、输出目录及仍保留的输出文件所有者设为 daemon 用户，并把 DACL 重建为仅 daemon 用户与 `SYSTEM`；遇到 junction、符号链接、异常嵌套或硬链接时会拒绝启动。

Phase 1 没有给 Named Pipe 设置自定义内核 DACL，因此部署安全性依赖运行目录 token 和 Windows 账户边界。需要跨用户调用时，不应复用此方案，应增加明确的 Pipe DACL、客户端身份校验和独立授权模型。

## 本机管理中心

管理中心是常驻服务的本机管理员控制面，不是远程或多用户运维服务。它只绑定 IPv4 loopback；MCP 不暴露配置修改 API，也不返回私钥内容。真实命令和传输仍由 daemon 独立执行目标映射、平台处理、策略、超时、并发、输出/文件配额和审计检查。OpenSSH `full-access` 跳过命令 allow-list 以及本机/远端传输根目录的范围匹配，并把有效传输方向固定为双向；AccessClient `full-access` 只跳过命令 allow-list，文件传输固定拒绝。两者都不绕过其他限制，并且每次保存 full-access 目标都要求服务端校验的显式确认。开发者 `--demo` 模式只使用内置模拟结果，不连接 daemon 或 SSH。

管理中心不接受密码、口令、AccessClient URI/票据/原始参数、任意 OpenSSH directive、`ProxyCommand` 或原始 `ProxyJump`。私钥生成和一次性路径导入只在“全局设置”中进行；生成算法限定为 Ed25519 或 RSA 3072。RSA 公钥记录虽然使用 `ssh-rsa` key type，连接仍由 OpenSSH 协商 RSA-SHA2，不会自动开启旧 SHA-1 `ssh-rsa` 签名。OpenSSH 目标和可选堡垒机只能提供结构化 host、port、user 和全局密钥 `keyId`，代理跳转只引用后端生成的固定别名。AccessClient 目标只保存 Plink 路径、物理网关 host/port/user、用于选择 PuTTY pipe 的共享逻辑 host、目标展示端点和预期 hostname。用户名只接受普通安全段，或严格的 `portalUser/targetIPv4/systemUser` 三段透传格式。v3 profile 不接受 `identityFile`，也不保存导入源路径。发布时，服务端按 `keyId` 从受保护的全局密钥库解析 OpenSSH 私钥，并把私钥与 `known_hosts` 复制到 `%LOCALAPPDATA%` 下 ACL 仅允许当前用户与 `SYSTEM` 的 staging revision；AccessClient 目标不生成或复制私钥和 `known_hosts`。

全局导入源和密钥库私钥都必须是直接引用的单链接 regular file；路径 `lstat` 身份必须与打开句柄 `fstat` 一致，复制期间设备、inode、链接数、大小、修改时间和状态变更时间不得变化，复制完成后还会重新核对源路径身份。密钥库以随机 `keyId` 目录和原子 manifest 保存公钥元数据，私钥目录、manifest 和临时 mutation 目录均经过 ACL 加固；密钥删除前会检查当前及保留 revision 的引用，避免留下失效的机器配置。

managed root 必须位于已就绪的本地固定磁盘，UNC、映射网络盘、device path、ADS 和含 reparse point 的祖先路径会被拒绝。每个 revision 在 daemon 仍运行旧配置时完成文件同步、ACL 加固、私钥解析、host 条目查找、结构化配置生成和发布前后的 `ssh -G` 最终值校验。active pointer 提交后，daemon 在同一 Named Pipe、runtime token、审计和 output store 上原子替换 `TargetRegistry + SshExecutor` generation；候选加载失败会恢复 pointer 并继续使用旧 generation。首次配置才使用 activation gate 启动 daemon。active pointer 同时记录上一 revision，系统只保留 active 与一个 rollback revision，并在删除候选 revision 前重新证明 active pointer 不再引用它。

可识别的 v2 fleet 和旧单目标 revision 仍会先按其已托管凭据恢复，随后由服务端把 revision 内的私钥导入全局密钥库、按指纹去重，并发布只含 `keyId` 的等价 v3 profile。迁移不访问最初的外部导入路径；若迁移失败，旧 revision 保持活动并报告 `KEY_MIGRATION_FAILED`，不会提交部分迁移状态。

managed lease 复用 daemon runtime lease 的所有者令牌和陈旧锁回收协议，阻止两个管理服务同时修改同一 managed root；HTTP 层也让密钥生成、配置发布、连接检测与命令执行互斥。存在任何 Gateway 活动执行时，热加载以 `CONFIG_BUSY` fail closed，不会并行排空两个 generation。进程启动、静态资源加载或 HTTP listen 失败时会关闭已创建的 daemon 并释放 lease。

管理服务从不自动运行或信任 `ssh-keyscan`。目标和堡垒机条目必须已经存在于导入的 `known_hosts`；非 22 端口按 OpenSSH `[host]:port` 形式查找。生成的端点配置强制 `IdentityAgent none`、`IdentitiesOnly yes`、禁用 password/keyboard-interactive，并把首选认证限制为 `publickey`。浏览器只会收到密钥 `keyId`、名称、算法、指纹、公钥、创建时间、来源和机器引用关系；不会收到托管私钥路径、导入源路径、`identityFile`、私钥内容、导入文件内容或外部命令错误详情。导入源路径由管理员在本机页面主动提交，但服务端不会把它回显或放入后续状态响应。

OpenSSH 首次公钥安装由用户明确点击“自动启动安装”后在本机终端中进行。网关只拼接固定认证选项和经过校验的目标字段，密码提示由 OpenSSH 终端处理，不会被网关读取、保存或写入命令行参数；远端安装脚本只追加所选公钥并设置账户 `.ssh` 权限。

应用层堡垒机透传目标不是 `ProxyJump`：它通过结构化三段用户名让入口 SSH 服务选择后端资产。每个透传会话必须作为独立目标，不能同时再配置页面中的堡垒机跳转。此模式下 host-key 校验和 `ssh_target_info` 看到的是透传入口的 SSH 主机密钥；Gateway 不声称取得或验证后端资产本身的主机密钥。管理员必须通过独立可信渠道核验入口指纹。

HTTP server 固定绑定 `127.0.0.1`，产品入口默认端口 52075；不能绑定外部网卡。每次启动生成独立的 256-bit 首次授权 token，启动 URL 通过 fragment 携带它，页面读取后立即清除 fragment。首次鉴权成功后签发 HttpOnly、SameSite=Strict、Path=/、30 天滚动有效期 Cookie；之后不需要 URL token 或浏览器 JavaScript 存储。Cookie 的 HMAC-SHA256 签名绑定完整 origin 和到期时间，托管目录 browser-session.key 保存经 ACL 加固的随机签名密钥，因此服务重启不会撤销浏览器授权。Cookie 名包含端口；Cookie 本身不能由浏览器按端口隔离，其他本机服务仍属于同一账户信任边界。本机 HTTP 不设置 Secure，部署不得改为对外 HTTP。

UI token 与 `runtime.json` 中的 gateway token 完全独立。Node 后端读取 gateway token 以建立 Named Pipe 会话，但不会把它、内部 RPC request ID 或 daemon 的 `outputRef` 返回浏览器。MCP 的 `ssh_open_admin` 由本机 MCP 进程调用 Windows 默认浏览器打开带 token 的 URL，只向 Agent 返回是否成功，不把 URL 或管理员 token 放入 MCP 结果。需要分页读取输出时，后端只向页面返回另一枚随机 `resultId`，并在内存中以有界、按过期时间清理的映射保存实际 `outputRef`。

所有 `/api/*` 都只接受 `POST application/json`，并同时要求：

- `Host` 精确等于当前 `127.0.0.1:PORT`
- `Origin` 精确等于当前本机 origin
- `Sec-Fetch-Site` 存在时只能是 `same-origin`
- 首次授权 header 通过恒定时间比较，或 Cookie 签名及有效期校验通过

管理中心不返回 CORS 许可，跨站预检和其他 HTTP 方法会被拒绝。上述检查共同防御恶意网页发起的 CSRF 和 DNS rebinding；请求体、连接数、header 数量及接收时间也有硬上限。静态资源只从固定文件清单加载，不提供任意路径或目录浏览。

页面使用严格 CSP 和同源安全 header。目标描述、命令及远端 stdout/stderr 只作为文本写入页面，不通过 `innerHTML`、ANSI 终端解释或自动链接执行。远端输出仍可能包含秘密，因此不要截图、复制到不受信任的网页，或在不可信浏览器扩展可见的环境中使用真实模式。

管理中心同时最多接受一个同步前台操作；其取消按钮和未完成的响应断开会通过原 RPC request ID 请求取消。通过任务接口启动的执行和传输则由 daemon 并发上限控制，HTTP/MCP 请求结束或断开不会隐式取消，必须使用 `runId` 显式取消。管理服务收到退出信号时会先停止 HTTP server；daemon 关闭会取消活动任务并等待收尾。若进程被强制终止，Job Object 仍负责清理本机受管进程树。

loopback 和 UI token 主要隔离普通网页，不构成同一 Windows 账户内的沙箱。恶意本机进程、调试器或高权限浏览器扩展仍可能读取页面或进程内存；这类威胁必须使用独立 Windows 身份和 OS 级隔离处理。不要分享完整管理 URL。撤销所有浏览器授权时，停止服务、删除托管目录中的 browser-session.key 后重启；仅重启会轮换首次授权 token，不会撤销现有 Cookie。

## SSH 约束

daemon 固定启用：

- `BatchMode=yes` 和 `NumberOfPasswordPrompts=0`
- `ConnectionAttempts=1` 和配置限定的 `ConnectTimeout`
- `StrictHostKeyChecking=yes`
- 指定的 `UserKnownHostsFile`，并禁用全局 known-hosts 回退
- 禁用 agent/X11 forwarding、所有端口转发、local command、escape command line
- 禁用 ControlMaster/ControlPersist/ControlPath 和密钥自动写入 agent
- 禁用管理员配置注入的 `RemoteCommand`，固定普通 session 类型
- `-T`，不分配 PTY；Linux/macOS legacy 单行命令使用 `-n` 关闭远端 stdin；结构化 Bash 及 Windows PowerShell/cmd 包装脚本只通过一次受管 stdin 发送有界 payload

这些约束写在 daemon 生成且 ACL 受保护的 wrapper `ssh_config` 中，并位于管理员配置之前；OpenSSH 的首次取值规则使它们同时约束最终目标和 `ProxyJump` 跳板目标。wrapper 不全局设置 `StdinNull`，因为 ProxyJump 子进程需要标准输入输出承载隧道。结构化执行只允许平台固定入口：Windows 为 PowerShell 或经 PowerShell 启动的临时 cmd 脚本，Linux/macOS 为 `bash --noprofile --norc -s`。调用方不能选择任意本机/远端 shell 可执行文件，也不能把交互输入继续转发到远端。

AccessClient 适配器只复用 PuTTY 已存在的共享连接。每个配置 generation 中，每台 AccessClient 目标最多持有一条 Plink 下游会话；同一目标严格 FIFO，不同目标可并行。Plink 固定使用 `-batch -share -loghost <sharingHost> -noagent -a -x -no-trivial-auth`、一个必定失败的 `-proxycmd` 和一个故意不匹配的 `-hostkey`；最终连接参数仍是独立保存的物理网关 host。共享连接不存在或执行期间消失时，因此不能降级为普通 SSH 认证。旧配置未保存 `sharingHost` 时继续使用物理网关 host，避免改变既有共享会话的选择语义。

Windows 管理中心的“准备会话”接口只接受当前已保存目标的 alias 和配置 revision，不接受注册表路径、命令、AccessClient 参数或凭据。服务端从已保存目标解析显式 `sharingHost`，只临时修改当前用户 PuTTY `Default Settings` 下固定的 `LogHost`；缺少显式标识的旧配置必须先重新保存，不能直接准备。准备前仅用 `tasklist.exe` 记录现有 `putty.exe` PID，不读取窗口、剪贴板、进程命令行、密码、OTP 或票据。检测到新 PuTTY PID 后保留 750 毫秒启动窗口再恢复旧值；两分钟超时、管理员取消、异常和管理服务关闭也会恢复。同一时间最多准备一个目标，准备期间配置修改被拒绝。

恢复所需的旧值写入本机 managed runtime 下的原子占位 marker。启动时若发现中断 marker，只有注册表当前值仍等于本次临时值时才写回旧值；若管理员已手工修改则保留管理员的新值。marker 已存在、内容无效或恢复失败时准备流程 fail closed，不会覆盖另一次准备。检测到新 PuTTY PID 不能证明目标资产或共享 pipe 正确，管理员仍须完成 AccessClient 登录、手工处理首次 PuTTY 主机密钥确认，并使用固定 hostname 探测确认机器身份。

下游 PTY 先只接收不含命令和 stdin 的固定 broker bootstrap。broker 关闭输入回显并返回带 128-bit session nonce 的 READY 与 hostname；本机严格匹配预期 hostname 后才发送命令。每条命令另有单调 sequence 和独立 128-bit nonce，命令与 stdin 使用 Base64 帧传入，输出由专属 pipe 编码为严格的 BEGIN/DATA/END ASCII 行。控制帧在原始字节上精确解析，ANSI/OSC 清理只作用于 DATA 解码后的内容；命令输出即使伪造协议文本也不能提前结束结果。无 stdin 的命令接空输入，有 stdin 的命令只接已经完整解码的有限数据，不继承 broker 控制 stdin。命令的输出 pipe 必须 EOF 后才发送 END，因此仍持有输出句柄的后台进程不会把延迟输出污染到下一条命令。

活动命令取消、超时、输出 sink/write/parser 错误、hostname 不匹配或子进程退出都会 poison 并销毁整条 Plink/Job；清理完成前不会执行下一条命令，结果不确定时不会自动重放。排队中且尚未发送的取消只移除该请求。持久会话空闲 60 秒回收、绝对寿命 10 分钟且无 keepalive；关闭 AccessClient 窗口后，已有共享 transport 最长可能继续到回收点。配置 reload、候选 generation 失败、daemon stop 和父 Node 进程异常退出都会显式回收受管进程树。适配器不枚举或关闭用户的 PuTTY 窗口，不读取 AccessClient 密码、URI、票据或进程命令行。

Agent 只能提交公开的不可变目标 ID、当前/历史公共别名，以及受 schema 约束的 legacy 命令、结构化 `shell/cwd/env/script`、任务句柄或传输路径引用；Full access 文件传输还允许提交 Gateway 本机的合法绝对路径。所有目标引用先解析到同一条策略记录，历史别名不会绕过禁用、命令或传输授权。不存在目标时，错误最多返回少量当前公开别名作为候选，不返回 OpenSSH 内部别名、host、user、key、路径或历史别名。`agent_ssh` 只是 Codex 本机 MCP 服务名，不是可授权目标。

管理员配置的 `ProxyCommand` 会在本机执行，并继承 daemon 的运行身份和环境。它属于受信任配置的一部分，必须像可执行代码一样审查和保护。

## Host Key

OpenSSH 模式下，缺少 `known_hosts`、目标 key 不匹配或首次出现未知 key 时连接会失败，不会自动接受或更新。主机指纹必须通过独立可信渠道核验。密钥轮换应由管理员更新文件，并留下变更记录。AccessClient 模式无法从共享命令通道独立取得后端资产 SSH host key，因此 `ssh_target_info` 返回空指纹和 warning；配置的 expected hostname 是防止共享到错误资产的附加检查，不能替代 AccessClient 管理员对资产和堡垒机的信任校验。

gateway 注入 OpenSSH 配置语境的管理员 config 与 known-hosts 路径禁止 `$`，因此 `${ENV}` 不能把 OpenSSH 实际读取位置替换成 daemon 未校验的文件；Windows `%` 会按 OpenSSH 语法转义为 `%%`。

## 命令策略

allow-list 按 UTF-8 字符串精确匹配整条 legacy 命令，命令不能包含 NUL 或换行。不接受正则、通配符或参数模板；远端命令仍由远端 shell 解释，因此每个允许项都必须按可执行代码审查，避免命令替换、重定向和 shell 运算符扩大权限。allow-list 不允许结构化 `cwd`、`env` 或多行 `script`，因为这些上下文无法由现有精确单行白名单安全表示。

`mode: full-access` 必须按目标显式配置。它允许 Agent 在该远端账户权限内执行任意单行命令或结构化多行脚本；OpenSSH 目标还允许在 Gateway 本机与远端合法绝对路径之间双向传输，AccessClient 目标的传输能力固定为 `deny`。Full access 可读取、修改或删除远端数据、安装软件和创建持久化；它不是沙箱，也不提供命令级或路径级最小权限。结构化 shell 名虽然固定，脚本正文仍是任意远端代码；`cwd` 和 `env` 只减少转义成本，不降低权限。应使用专用低权限 Gateway 账户与远端账户、目录/服务 ACL、容器或虚拟机限制影响范围，并只在确实需要开放式运维时启用。

`mode: deny` 永远拒绝执行，可用于保留但冻结目标。禁用目标不会暴露内部 `sshAlias`。

`target.check` 不是通用命令后门。其 RPC schema 只接受公共目标别名，服务端固定运行 `hostname`；OpenSSH 最长使用 `min(target.maxTimeoutMs, 15000)`，AccessClient 因共享交互 shell 建立较慢而使用 `min(target.maxTimeoutMs, 30000)`。它复用并发、取消、进程清理、输出限制和审计管线，并有意独立于 allow-list/full-access/deny 命令策略，以便管理员诊断认证链路；禁用目标仍然拒绝检测。返回值不包含 stdout、stderr 或 `outputRef`，仅在退出码为 0 时返回经过字符集和长度校验的 hostname。

命令和结构化 payload 原文不会写入 gateway JSONL 审计，但可能出现在调用方会话或工具日志中。Windows 目标还可能被 PowerShell Script Block Logging、AMSI、Defender/EDR 或其他系统审计记录；Linux/macOS 目标可能被 shell、auditd 或会话记录设施记录。不要把密码、token、私钥或其他秘密放入命令、脚本或环境变量。payload SHA-256 仍是可枚举的稳定指纹。

## 长任务与任务句柄

`task.start`/`ssh_start` 创建 daemon 持有的任务，并返回随机 256-bit `runId`。这与同步 `exec.run` 不同：启动请求所在的 IPC/MCP 连接断开不会取消任务，新的已认证连接可以继续读取状态和日志或显式取消。调用方必须在不确定“启动响应是否送达”时避免自动重试，否则可能创建两个具有远端副作用的任务。

任务句柄不绑定某个 MCP 客户端身份。同一 Gateway 信任边界内，任何已认证且获得 `runId` 的调用方都可以执行 `status`、`tail` 或 `cancel`；因此 `runId` 不应写入公开日志。任务状态和日志只在内存中按 TTL 保留，daemon 重启后旧句柄失效。daemon 正常关闭会取消并等待活动任务；异常退出仍依赖 Job Object 清理本机 SSH/SFTP 进程树。

`ssh_tail` 使用不透明 cursor 返回有界滚动 stdout/stderr。消费者必须检查 `droppedBytes` 和 `hadDecodingErrors`，不能假定从任意旧 cursor 都能恢复完整日志。取消和超时是协作式任务终态：Gateway 会中止本机受管进程，但远端已主动脱离 SSH 会话的进程仍可能继续。

## 文件传输

OpenSSH 受限目标的文件传输使用独立于命令 allow-list 的 fail-closed 授权，默认 `transfer.mode: deny`。管理员必须显式选择 `upload`、`download` 或 `bidirectional`，同时授权命名本机根目录、远端绝对路径根目录、单文件/总字节/文件数配额和最大超时；`upload` 模式同时允许本机到远端的目录同步，`download` 不允许反向上传。OpenSSH Full access 目标的有效传输权限固定为 `bidirectional` 和全部合法绝对路径；旧配置中的传输方向和根目录不会缩小该范围。AccessClient 目标无论命令策略为何都固定为 `deny`，任何上传、下载或同步请求都会在授权层失败。实际 OpenSSH Gateway `transfer` 块中的配额和超时仍会生效，没有该块时使用默认配额和最长 3,600,000 毫秒超时。

受限调用只能提交本机根目录别名和相对 `localPath`，不会看到该别名对应的绝对路径。Full access 调用可以省略 `localRoot`，但此时 `localPath` 必须是 Gateway 本机原生绝对路径；提供 `localRoot` 时仍按兼容的根目录加相对路径形式处理。受限远端路径必须位于授权根目录内，Full access 远端路径可以位于目标账户可访问的任意正常文件系统根下。两种模式都拒绝符号链接/reparse point、非常规文件、Windows device/UNC 路径和不规范远端绝对路径；受限相对路径还拒绝 `..` 和根目录逃逸。上传会预检目标和 partial 的所有现存远端祖先，下载会在读取远端指纹时做同类检查；当时观察到 symlink、junction 或其他 reparse point 时会 fail closed。SFTP 只接收 Gateway 生成、长度有界且逐字段转义的 batch，不接受调用方提供的原始 SFTP 命令。

上传前把本机源文件复制到私有 spool，并在复制期间核对文件身份和 SHA-256，避免把已校验路径直接交给另一个进程造成 TOCTOU。上传写入内容寻址的远端 partial，校验后再发布；下载写入与目标/路径/hash 绑定的私有 partial，校验后再发布到本机目的路径。`resume` 会保留或复用 partial，但校验不一致时回退到完整传输。`overwrite: true` 明确允许替换目标，具有破坏性。Full access 只扩大合法路径范围，不会绕过单文件/总字节/文件数配额、超时、校验和、受控 partial 发布、取消、进程清理或审计。

`dryRun` 保证不发布目标数据，但仍可能扫描/读取本机文件、计算哈希、查询远端文件哈希或检查目标状态。Full access 因此可以读取或覆盖 Gateway 运行账户能够访问的本机私钥、云凭据、配置、源代码和用户文件；隐藏 SSH 凭据配置并不能阻止 Agent 通过已授权的全路径文件工具读取其他可访问文件。生产部署应让 Gateway 使用专用低权限 Windows 账户，并用 ACL 把运行目录、私钥和其他敏感数据与可传输工作区隔离。`ssh_sync` 仅做本机到远端的单向文件同步，不删除远端多余文件；排除规则和 `verifyExisting` 只影响扫描、跳过与覆盖判断，不能扩大受限目标的授权范围。stdout、任务结果和传输审计只返回通用进度及计数，不应加入实际本机绝对路径或凭据。

## 机器信息与 Docker 预检

`ssh_target_info` 和 `ssh_docker_preflight` 使用 Gateway 内置、ASCII 固定、输出有界的探针，不接受任意命令文本。探针输出必须通过严格结构和字符集校验后才会成为公共结果。机器 ID 由远端原生机器标识与本机私有 key 做 HMAC 派生，不返回原生标识；它在同一 managed root/key 范围内稳定，但不是跨 Gateway 的全球标识。返回的 SSH host-key 指纹来自受信任配置检查，不能替代管理员通过独立渠道完成的首次指纹核验。

目标信息会向 Agent 暴露 hostname、系统/内核/架构、磁盘容量和 Docker/Compose 版本等运维元数据。Docker 预检额外检查 daemon、Compose 配置、请求端口、容器状态/健康和磁盘，并只对显式 `full-access` 目标开放；项目目录必须是对应平台的本地绝对路径，Compose 文件只能是项目内安全相对路径。预检固定为只读观测，不会构建、启动、停止或删除容器。

## 进程清理

Windows supervisor 在挂起状态创建 `ssh.exe`，先加入带 `KILL_ON_JOB_CLOSE` 的 Job Object，再恢复运行。超时、取消、客户端断连、daemon 关闭或 daemon 异常退出都会关闭控制通道并终止 Job 中的 SSH、ProxyCommand 和其他后代进程。生产路径不允许回退为只杀根进程。

该保证只覆盖本机 gateway 启动的进程树。远端命令主动分离出的任务，例如 `nohup`、服务、计划任务或 PowerShell `Start-Process`，可能在 SSH 会话超时或取消后继续运行；`full-access` 使用者必须通过远端账户权限、服务管理策略和幂等命令自行约束这类任务。

## 输出与审计

stdout/stderr 可能包含敏感数据。同步执行的内联结果会返回调用方，每个流的内联预览硬上限为 8 KiB；超出后完整内容写入受保护运行目录，以随机 256-bit `outputRef` 读取并按 TTL 清理。为了兼容已有 managed revision，配置仍可包含历史上更高的 `inlineOutputBytes`，但 OutputStore 会在产生 RPC 结果前强制收紧到 8 KiB。`ssh_read_output` 返回原始 Base64，`ssh_read_output_text` 默认使用绑定输出引用、流和位置的不透明 cursor，并在 UTF-8 完整字符边界分页；显式传入的旧字节偏移若落在合法字符中间会前移到字符末尾。文本接口会报告真正的不合法字节，调用方不能把 `hadDecodingErrors` 的输出当成可信文本。长任务另有内存滚动日志，通过 `ssh_tail` 的不透明 cursor 读取。单次执行上限之外，所有活动写入与 retained output 还共享全局字节和条目配额；并发 append 会先原子计入配额，删除、过期、abort 或只返回内联结果时归还。启动扫描会核对 metadata 与实际规范文件的大小，损坏项不会进入配额账本。调用方不应把结果转发给不受信任的模型、日志或用户。

审计 JSONL 只允许固定字段，使用服务端随机 `executionId` 关联事件，并记录命令/结构化 payload SHA-256、UTF-8 长度、目标公共别名、结果类型、退出码、时长和字节计数。它不记录客户端名、客户端 RPC request ID、原始命令/脚本/环境、stdout、stderr、token、路径或 `outputRef`。`exec.started` 必须落盘并同步成功后才会启动 SSH。传输审计只记录 `runId`、目标、方向、dry-run 标志、固定原因码和文件/字节计数。

审计文件有配置的硬上限，并为所有允许的并发执行预留取消/完成记录空间。达到普通写入阈值后 `exec.started` 会 fail closed；系统不会自动删除历史审计。管理员必须停机归档或清空日志后再启动，不能依赖运行中重命名已打开文件。

审计脱敏是纵深防御，不应成为向审计事件加入任意文本的理由。

## 已知限制

- 不提供多租户或跨 Windows 身份授权。
- 不解析远端 shell 语法；legacy allow-list 的安全性取决于精确匹配，结构化执行只允许在 `full-access` 下使用。
- 不自动完成密码、sudo、MFA 或 host-key 确认。
- 长任务只跨 MCP/RPC 客户端断连存活，不跨 daemon 重启持久化；任务日志是有界滚动缓冲，不是完整构建日志归档。
- 文件同步只支持本机到远端、不会删除远端多余文件；不提供独立文件浏览、远端到本机目录同步或调用方自定义 SFTP batch。Full access 仍可通过单文件上传/下载访问任意合法绝对路径。
- 路径检查是传输前的纵深防御，不是无竞态的文件系统沙箱。远端路径预检与后续 SFTP 之间仍可能发生并发替换，本机已检查的祖先目录也可能被有权账户替换；受限本机和远端根目录应由可信账户独占。需要抵御恶意远端账户时，应使用远端原生 helper、chroot/container 或服务端文件 API 强制约束。
- SSH 退出码 255 也可能由远端命令返回，因此不会被武断分类为传输错误。
- Windows PowerShell 目标使用 Windows PowerShell 5.1 兼容语法。PowerShell 7 专属语法需要由目标显式调用 `pwsh.exe`，且仍受当前目标策略约束。
- timeout/cancel 终止本机 SSH 进程树，不保证终止远端已经脱离会话的后台任务。
- IPC 帧限制为 1 MiB，但当前增量解析会反复合并碎片。持有会话 token 的本地客户端可用极端碎片化输入增加 daemon 的 CPU 开销。
- 审计中的命令 SHA-256 是稳定指纹，不等同于不可逆匿名化。能够猜测 allow-list 的审计读取者可以离线枚举命令，因此审计文件仍必须按敏感数据保护。
- 热加载不并行排空旧、新 generation；有活动执行时配置保存返回 `CONFIG_BUSY`，管理员必须在执行结束后重试。


## 原生 Tailscale SSH 的信任边界

`tailscale-ssh` 使用已经登录的本机 Tailscale daemon 作为节点与 SSH 主机密钥来源。每次操作先以受管进程执行管理员配置的 `tailscale.exe status --json`，限制输出和查询时限；必须匹配唯一的 tailnet peer、有效 Tailscale 地址和已公布的 SSH 主机密钥。未知节点、缺少密钥或本机未登录时均拒绝，不使用 `ssh-keyscan`，不关闭主机校验，也不回退到本机私钥认证。完整 status JSON 和本机 CLI 错误不进入公共输出或审计。

SSH 通过固定的 OpenSSH 可执行文件直连解析后的 Tailscale IP，使用 runtime 下受保护的每次调用专用配置及 known_hosts。正常完成或失败后清理临时文件；进程异常退出可能留下仅含节点地址、公钥及连接选项的受保护临时目录，不含私钥。用户 ssh_config、代理、密钥、SSH agent、密码和转发均被禁用。本版要求 Windows 正常 Tailscale 网络模式；不提供 userspace-networking 代理。

远端授权由 tailnet 网络规则、SSH 策略及远端账号权限控制；Gateway 仍独立执行自身命令策略、限额、取消和审计。Tailscale 设备身份的权限可能大于 Gateway 对 Agent 授予的权限，不能用本机同账户隔离假设替代操作系统边界。目标名称解析与主机密钥均跟随本机 daemon 当前可信的 tailnet 状态。

Tailscale check 模式需要管理员交互认证，Gateway 不批准认证链接或修改 tailnet 策略。Tailscale SSH 仅支持 Linux/macOS 服务端；本次扩展不改变 Gateway 的 Windows 运行端限制。本版在配置、注册表授权和 UI 中关闭 Tailscale SSH 的文件传输，包括 Full access。取消保证仍限于本机进程树，不能保证撤销已经发生的远端副作用。
