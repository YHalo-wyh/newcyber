# PoC-in-GitHub 离线参考索引

NewCyber 可以把 `nomi-sec/PoC-in-GitHub` 当作**漏洞参考元数据库**使用，但不会把其中的 PoC 当作自动执行插件。

## 使用方式

1. 在有网络的环境准备一份 `nomi-sec/PoC-in-GitHub` 本地仓库副本。
2. 打开 NewCyber 的赛题目录页面，在“相关漏洞 / PoC 参考”区域点击“导入本地索引”。
3. 选择该仓库的根目录。NewCyber 会读取 `YYYY/CVE-YYYY-NNNN.json`，生成自己的紧凑离线索引并保存到 Electron `userData` 目录。
4. 以后打开赛题目录时不需要再次读取整个 PoC 仓库：NewCyber 直接加载缓存索引，根据题目文本、文件名、技术栈、Finding 和 CVE 自动筛选相关项。
5. PoC-in-GitHub 更新后，再点一次“更新本地索引”即可重建缓存。

## 索引内容

每个 CVE 只保留用于检索和人工判断的元数据：

- CVE ID / 年份
- PoC-in-GitHub 对应 JSON 的源链接
- 代表性 GitHub 仓库名称和 URL
- 仓库 description / topics
- stars / forks（仅作为参考排序信号）
- 从上述文本抽出的产品、组件和漏洞类型关键词

不会把 PoC 源码、二进制附件、release 或脚本复制进 NewCyber。

## 匹配规则

直接出现 `CVE-YYYY-NNNN` 时使用最高优先级精确匹配。没有 CVE 时使用离线倒排索引，把产品/组件词和常见漏洞类型组合起来打分，例如 `log4j + rce`、`flask + ssti`、`wordpress + file-upload`。高频泛词会被降权，稀有组件词权重更高。

输出会同时显示：匹配 CVE、分数、命中关键词、命中原因、简短说明、代表性公开仓库和 PoC-in-GitHub 元数据源链接。它的定位是**给出值得对照的历史漏洞线索**，不是断言赛题一定存在该 CVE。

## 安全边界

PoC-in-GitHub 自身收集的是互联网上的公开 PoC 仓库，其中可能包含恶意或危险内容。因此 NewCyber 默认坚持以下边界：

- 不自动 clone / download 匹配到的 PoC 仓库；
- 不执行 PoC、脚本、二进制或安装依赖；
- 不自动对远程目标发送验证请求；
- 不因为关键词相似就把“相关参考”升级成“漏洞已确认”；
- 报告和 UI 保留匹配原因，便于人工复核。

这样可以在线下比赛提前准备完整元数据，比赛现场只做离线筛选，也不会让“找参考”变成新的不可信代码执行入口。
