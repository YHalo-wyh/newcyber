# Batch 19 · Offline Advisory Applicability

NewCyber 的 PoC-in-GitHub 关联负责回答“有哪些历史漏洞/PoC 值得对照”，Batch 19 进一步回答“题目里实际解析出的组件和精确版本，是否落入本地 advisory 给出的 affected range”。

## 比赛前一次准备

在联网环境提前准备一个 OSV-compatible JSON advisory 目录。目录可以按生态或年份分层，只要文件最终是 OSV 风格 JSON 即可。进入 NewCyber Workspace 后点击“导入 Advisory 索引”，选择这个目录。NewCyber 会递归读取 JSON、压缩成自己的本地索引并缓存在 Electron userData 中。之后打开任何赛题目录都会自动使用，不需要重复选择，也不会在比赛现场联网。

NewCyber 只解析 advisory 元数据；不会安装依赖、不会下载或执行 PoC、不会向远程目标发送验证请求。

## 当前判断链

1. Batch 18 从 package/lock/requirements/pom/Gradle/Go/Cargo/Composer/Gem/Dockerfile/banner 中提取组件与精确版本。
2. Batch 19 用 ecosystem + package name 精确匹配离线 advisory。
3. 如果 `affected.versions` 明确包含当前版本，判为 `AFFECTED`。
4. 如果 advisory 提供 `SEMVER` / `ECOSYSTEM` ranges，按 `introduced / fixed / last_affected / limit` 构造区间并比较当前版本。
5. 当前版本明确落在所有可比较 affected range 之外时标记 `NOT AFFECTED`。
6. 版本格式无法可靠比较、advisory range 信息不足或只有声明约束没有 resolved version 时保持 `UNKNOWN`。
7. Advisory 结果再回流到 PoC-in-GitHub：`AFFECTED` 提升 PoC 优先级，`NOT AFFECTED` 降低同 CVE PoC 优先级，`UNKNOWN` 不做结论。

## 为什么保留 UNKNOWN

不同生态的版本语义并不完全一致，尤其 Maven、发行版 backport、vendor build、Git commit range 等不能安全地用一个“万能 semver”覆盖。Batch 19 第一版只对常见数字版本和明确 OSV range 做确定性比较。不能可靠比较时宁可输出 `UNKNOWN`，也不输出错误的“已修复/安全”。

## 当前支持

技术栈侧已覆盖 npm、PyPI、Maven、Go modules、Cargo、Composer、RubyGems、Docker 以及部分通用 banner；Advisory 索引接受 OSV-compatible `affected[].package`、`affected[].versions` 和 `affected[].ranges`。

后续可以继续补：

- ecosystem-specific comparator（Maven ComparableVersion、PEP 440、Go pseudo-version 等）；
- Git range / commit introduced-fixed 判断；
- distro backport / package revision；
- GHSA/CVE/CWE/CVSS 与 PoC 证据的统一排序；
- 增量索引更新和更紧凑的磁盘格式。

## 结论语义

- `AFFECTED`：当前精确版本被本地 advisory 的明确 versions/range 覆盖，是高价值静态版本证据。
- `NOT AFFECTED`：当前精确版本未落入该 advisory 提供的可比较 affected range。只针对该 advisory/版本关系，不代表组件整体安全。
- `UNKNOWN`：证据不足或版本语义无法可靠比较。绝不等价于安全。
