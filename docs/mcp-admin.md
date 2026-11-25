# MCP 机器接入与管理

本能力允许 Codex 或其他 AI Agent 在管理员显式授权后，通过 MCP 工具查询管理中心配置、与用户确认接入细节，并直接完成本机 Web 管理中心支持的机器接入与运维管理操作。

## 开启方式（默认关闭）

为保持默认最小权限边界，MCP 配置管理**默认关闭**：

1. **Web 管理中心开关（推荐）**：打开本机管理中心 →「全局设置」→「MCP 管理权限」，开启「允许 MCP 管理机器与配置」。该设置持久化保存在托管目录经 ACL 加固的 `mcp-admin-policy.json` 中，切换后**立即生效**，无需重启 `agent-ssh-service` 或 `agent-ssh-mcp`。
2. **启动参数强制开启**：启动服务时传入 `--allow-mcp-admin`：

```powershell
npm run start:service -- --allow-mcp-admin
```

传入 `--allow-mcp-admin` 时，当前服务进程强制开启 MCP 管理权限（不改写磁盘上的持久化设置）；Web 页面会显示「已开启（启动参数）」并锁定开关，移除该参数重启后自动恢复原有持久化状态。

关闭状态下，Agent 调用 `ssh_admin_get_config` 仅能获知管理服务在线但 MCP 管理已关闭，不会泄露任何机器、路径、密钥或 revision；调用任意写入或管理接口均返回 `MCP_ADMIN_DISABLED`，并提示管理员在管理中心开启（可配合 `ssh_open_admin` 打开页面）。

## 安全约束

- **禁止自我提权**：MCP 永远不能调用 `/api/admin/mcp-admin/save` 修改开关状态。
- **不暴露私钥与任意路径导入**：MCP 仅能读取密钥 `keyId`、标签、算法、指纹与公钥，绝不返回私钥正文、托管路径或管理中心 token；从本机绝对路径导入现有私钥（`/api/admin/key/import`）仍仅限本机浏览器页面操作。
- **高危操作显式确认**：
  - 配置 `policyMode: "full-access"` 须在与用户确认后传入 `fullAccessConfirmed: true`；
  - 为 `allow-list` 机器开启文件传输须在与用户确认后传入 `transferAccessConfirmed: true`；
  - 删除机器（`ssh_admin_remove_target`）或删除托管密钥（`ssh_admin_remove_key`）须在与用户确认后传入 `removeConfirmed: true`。
- **不接触密码与 host key 绕过**：OpenSSH 首次安装公钥仍通过 `ssh_admin_launch_ssh_install` 打开本机交互终端由用户亲自输入密码，并且保持 `StrictHostKeyChecking=yes`；系统不会自动运行 `ssh-keyscan`。
- **乐观并发锁**：所有修改均携带 `expectedRevision` / `expectedKeyRevision`，与浏览器管理页面并发编辑时通过 `CONFIG_CONFLICT` / `KEY_REVISION_CONFLICT` 防止覆盖。

## MCP 管理工具一览

| 工具 | 对应管理页面能力 |
| --- | --- |
| `ssh_admin_get_config` | 读取服务状态、MCP 管理开关、当前 `revision` / `keyRevision`、分组、脱敏密钥列表、机器配置、全局工具路径及预设目录 |
| `ssh_admin_save_target` | 新增、修改或重命名机器（OpenSSH / Tailscale SSH / AccessClient；支持全部 4 档权限与文件传输配置） |
| `ssh_admin_set_target_enabled` | 启停指定机器的 MCP 访问 |
| `ssh_admin_remove_target` | 删除机器并撤销其访问（需 `removeConfirmed: true`） |
| `ssh_admin_check_target` | 经管理中心检测连接；AccessClient 首次成功时自动学习并保存 `expectedHostname` |
| `ssh_admin_manage_group` | 分组创建（`create`）、重命名（`rename`）、删除（`delete`）、移动机器（`move`）、排序（`reorder`） |
| `ssh_admin_generate_key` | 在托管密钥库生成 Ed25519 或 RSA 3072 密钥对，仅返回公钥与元数据 |
| `ssh_admin_rename_key` | 重命名托管密钥标签 |
| `ssh_admin_remove_key` | 删除未被任何活动或回滚 revision 引用的托管密钥（需 `removeConfirmed: true`） |
| `ssh_admin_launch_ssh_install` | 打开本机交互终端，协助用户向远端 `authorized_keys` 安装所选托管公钥 |
| `ssh_admin_save_provider_settings` | 保存全局 `tailscale.exe`（`provider: "tailscale"`）或 `plink.exe`（`provider: "accessclient"`）路径 |
| `ssh_admin_accessclient_session` | Windows 上准备（`prepare`）、轮询校验（`status`）或取消（`cancel`）AccessClient PuTTY 共享会话 |

## 典型对话接入流程

1. Agent 先调用 `ssh_admin_get_config` 获取现有分组、密钥、`defaultKnownHostsFile` 和 `revision`。
2. 若 MCP 管理未开启，Agent 提示用户（可调用 `ssh_open_admin` 打开页面）在「全局设置 → MCP 管理权限」开启。
3. Agent 向用户询问尚未确定的接入细节：IP/主机名、端口、登录账号、系统平台、连接方式、所属分组、使用哪把密钥（或是否新生成）、权限档位及高危确认项。
4. 细节确定后，Agent 依次完成：
   - 按需创建分组（`ssh_admin_manage_group`）或生成密钥（`ssh_admin_generate_key`）；
   - OpenSSH 机器如需安装公钥，展示公钥或调用 `ssh_admin_launch_ssh_install` 打开本机终端待用户完成认证；
   - 保存机器配置（`ssh_admin_save_target`）；
   - AccessClient 机器按需准备共享会话（`ssh_admin_accessclient_session`）；
   - 检测连接（`ssh_admin_check_target`）确认可用。
