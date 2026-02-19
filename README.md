# Rule Forge

Rule Forge 是一个规则配置生成项目，用于把 `entities/` 中的实体规则，按 `policies/` 的策略编排，生成可用于 Clash 和 Loon 的规则文件。

## 项目目标

- 统一维护规则实体（域名、关键词、IP 网段、GEOIP）。
- 通过策略文件定义“哪些实体归属哪个分组”。
- 自动生成目标平台配置，避免手工拷贝与错配。

## 目录结构

```text
rule-forge/
├── entities/                 # 规则实体库（按业务分类）
├── policies/
│   ├── groups.yaml           # 分组定义（Clash proxy-groups）
│   └── rule.yaml             # 规则归属策略（实体/标签 -> group）
├── scripts/
│   ├── generate_clash.py     # 生成 Clash 配置
│   └── generate_loon.py      # 生成 Loon 分组规则文件
└── README.md
```

## entities 格式

实体文件为 YAML，常用字段如下：

- `name`: 实体名
- `domains`: 精确域名
- `suffix-domains`: 后缀域名
- `keyword`: 域名关键词
- `ipv4s`: IPv4 CIDR
- `ipv6s`: IPv6 CIDR
- `geo-ips`: GEOIP 规则
- `tags`: 标签（用于 `policies/rule.yaml` 的 `tags` 匹配）

示例：

```yaml
name: Example
domains:
  - example.com
suffix-domains:
  - example.com
keyword:
  - example
ipv4s:
  - 1.1.1.1/32
ipv6s:
  - 2001:db8::/32
geo-ips:
  - CN
tags:
  - China Mainland Service
```

## 策略匹配规则

`policies/rule.yaml` 按从上到下顺序生效：

1. 先匹配到的策略优先级更高。
2. 同一个 entities 文件只会被引用一次：
   即被上方策略命中后，下方策略不再重复引用该文件。
3. 支持 `entities` 和 `tags` 两种匹配方式。
4. 支持通配选择器（如 `ads/*`、`*`）和目录/单文件选择。
5. `entities/demo.yaml` 被视为示例文件，生成时会自动排除。

## 生成 Clash 配置

```bash
python3 scripts/generate_clash.py -o clash.generated.yaml
```

输出内容包括：

- 内置基础配置（端口、模式等）
- 默认使用本地文件夹内的 `sub.yaml` 作为 proxies 列表
- 由 `policies/rule.yaml + entities/` 生成的 `rules`

说明：

- 当前 Clash 生成脚本不再读取 `policies/config.yaml`、`policies/proxy-providers.yaml`、`policies/proxies.yaml`。
- 这些内容已固化在 `scripts/generate_clash.py` 内。

## 生成 Loon 规则

```bash
python3 scripts/generate_loon.py -o loon
```

行为说明：

- `-o` 传入目录名（例如 `loon`），脚本会自动创建目录。
- 按“有规则的 group”分别生成独立文件。
- 文件名格式：`loon-<group>.txt`。
- 文件内容仅包含规则行，不包含策略名。

示例输出：

```text
loon/
├── loon-ads.txt
├── loon-main-direct.txt
├── loon-main-proxy.txt
└── loon-apple-service.txt
```

## 开发约束

- 欢迎共同维护规则，优化网络体验。
- 新增实体时，按分类放入 `entities/` 对应目录。

## 注意事项

- 本仓库仅提供规则管理维护，不提供 proxies 等服务。
- 请结合自身的 proxies 等文件来完成你的最终规则文件，不建议直接订阅本项目的产物
