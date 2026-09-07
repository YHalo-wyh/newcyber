function lineNumberAt(text,index) {
  return text.slice(0,Math.max(0,index)).split(/\r?\n/).length;
}

function evidenceAt(text,index,radius=220) {
  const start=Math.max(0,index-80); const end=Math.min(text.length,index+radius);
  return text.slice(start,end).trim();
}

function addFinding(findings, text, match, spec) {
  findings.push({
    id:spec.id,
    severity:spec.severity,
    title:spec.title,
    line:lineNumberAt(text,match.index),
    evidence:evidenceAt(text,match.index,spec.radius||260),
    meaning:spec.meaning,
    fix:{ target:spec.fixTarget, action:spec.fixAction, regression:spec.regression }
  });
}

function scanPythonSource(text) {
  const findings=[];
  const patterns=[
    {
      regex:/\btrust_remote_code\s*=\s*True\b/gi,
      id:'hf-trust-remote-code', severity:'high', title:'Hugging Face 允许远端自定义代码',
      meaning:'模型/Tokenizer 加载允许执行仓库中的自定义 Python 代码；若仓库或 revision 可被影响，供应链边界直接进入代码执行。',
      fixTarget:'from_pretrained()/AutoConfig 参数', fixAction:'能不用则移除 trust_remote_code=True；确需使用时固定仓库 revision/commit 并对代码做静态审计。', regression:'更换远端 revision 或插入自定义 modeling 文件后，加载路径不得自动接受未审核代码。'
    },
    {
      regex:/\b(?:torch\.hub\.load|hub\.load)\s*\(/gi,
      id:'runtime-model-code-fetch', severity:'medium', title:'运行期模型/代码加载',
      meaning:'运行过程中从 Hub/仓库解析模型或代码，需确认来源、revision、缓存优先级和本地覆盖路径。',
      fixTarget:'Hub 加载调用', fixAction:'固定可信 commit/tag，并显式记录 artifact hash；避免从攻击者可控字符串拼接仓库/入口。', regression:'同名本地缓存、不同 revision 或恶意镜像不能改变最终加载 artifact。'
    },
    {
      regex:/\b(?:os\.system|subprocess\.(?:run|Popen|call|check_call|check_output))\s*\([^\r\n]{0,500}\b(?:pip|python\s+-m\s+pip)\b/gi,
      id:'runtime-pip-install', severity:'high', title:'运行期安装 Python 依赖',
      meaning:'业务代码在运行时调用 pip 安装依赖；若包名、源或版本可控，可形成依赖供应链执行链。',
      fixTarget:'运行期 pip/subprocess 调用', fixAction:'把依赖解析移到构建阶段并锁定版本/hash；运行时不得根据用户输入安装包。', regression:'修改包名/索引地址/版本输入不能触发新的安装动作。'
    },
    {
      regex:/\bsys\.path\.(?:insert|append)\s*\([^\r\n]{0,300}(?:cwd|getcwd|dirname|request|upload|temp|tmp)/gi,
      id:'python-path-shadowing', severity:'medium', title:'Python import path 可被本地目录覆盖',
      meaning:'动态把工作目录、上传目录或临时目录加入 sys.path，可能让同名模块覆盖真实依赖。',
      fixTarget:'sys.path 动态修改', fixAction:'只加入固定只读目录，并在加载关键模块前校验 resolved path。', regression:'在工作目录放置同名模块时，关键 import 的 resolved path 仍必须指向固定依赖目录。'
    },
    {
      regex:/\b(?:pickle\.load|joblib\.load|torch\.load|dill\.load|cloudpickle\.load)\s*\(/gi,
      id:'unsafe-model-deserialization-call', severity:'medium', title:'可执行语义模型/对象加载',
      meaning:'加载 API 可能包含 pickle/dill/joblib 执行语义；真正风险取决于文件来源与加载参数。',
      fixTarget:'模型/对象加载调用', fixAction:'优先改用 SafeTensors/纯权重格式；必须加载 pickle 时先做独立静态扫描并约束来源/hash。', regression:'恶意 GLOBAL/REDUCE 样本必须在加载前被阻断，正常 checkpoint 仍可按预期读取。'
    }
  ];
  for (const spec of patterns) {
    for (const match of text.matchAll(spec.regex)) addFinding(findings,text,match,spec);
  }

  for (const match of text.matchAll(/\b(?:AutoModel\w*|AutoTokenizer|AutoConfig|PeftModel|SentenceTransformer)\.from_pretrained\s*\(([\s\S]{0,900}?)\)/gi)) {
    const call=match[0];
    const hasRevision=/\brevision\s*=/.test(call);
    const localOnly=/\blocal_files_only\s*=\s*True/.test(call);
    if (!hasRevision && !localOnly) addFinding(findings,text,match,{
      id:'hf-revision-unpinned',severity:'medium',title:'模型/Tokenizer revision 未固定',
      meaning:'from_pretrained 未固定 revision；同一仓库标识可能在不同时间解析到不同 artifact。',
      fixTarget:'from_pretrained 调用',fixAction:'固定不可变 commit SHA/revision，并记录权重、Tokenizer、adapter 的 hash。',regression:'仓库默认分支变化时，比赛/部署环境仍解析到同一 commit。'
    });
  }
  return findings;
}

function scanPackaging(text) {
  const findings=[];
  const lines=String(text||'').split(/\r?\n/);
  for (let index=0;index<lines.length;index+=1) {
    const line=lines[index].trim();
    if (!line || line.startsWith('#')) continue;
    if (/^--(?:extra-)?index-url\b/i.test(line)) findings.push({
      id:'python-extra-index',severity:'medium',title:'Python 包索引被重定向/追加',line:index+1,evidence:line,
      meaning:'requirements 中存在自定义 index/extra-index；多源解析时应检查同名包优先级和依赖混淆。',
      fix:{target:`line ${index+1}`,action:'使用受控单一源或显式锁定直接 URL/hash；检查内部包名是否可能被公开源抢占。',regression:'构造同名更高版本包时，解析结果不得切换到非预期源。'}
    });
    if (/^(?:git\+|https?:\/\/|file:|\.\.?\/|[A-Za-z]:\\)/i.test(line) || /\s@\s(?:git\+|https?:\/\/|file:)/i.test(line)) findings.push({
      id:'direct-dependency-reference',severity:'info',title:'直接 URL/VCS/本地依赖',line:index+1,evidence:line,
      meaning:'依赖不是普通版本解析；应固定 commit/digest 并确认本地路径是否可被赛题输入覆盖。',
      fix:{target:`line ${index+1}`,action:'VCS 固定 commit SHA，文件依赖固定 hash/只读路径。',regression:'改变分支 HEAD 或工作目录同名文件不能改变最终依赖内容。'}
    });
    const req=line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$/);
    if (req && !/^[-.]/.test(line)) {
      const constraint=req[2].trim();
      if (!constraint || (!/^==[^,;\s]+(?:\s*;.*)?$/.test(constraint) && !/--hash=sha256:/i.test(line))) findings.push({
        id:'dependency-not-locked',severity:'info',title:'依赖版本未完全锁定',line:index+1,evidence:line,
        meaning:'版本范围或未指定版本会让解析结果随时间变化；这本身不是漏洞，但会扩大供应链不确定性。',
        fix:{target:`line ${index+1}`,action:'比赛复现/关键环境固定已验证版本，必要时附 hash lock。',regression:'重新安装时依赖版本与 hash 应保持一致。'}
      });
    }
  }
  return findings;
}

function auditAiSupplyChain(input) {
  const text=String(input||'');
  const findings=[...scanPythonSource(text),...scanPackaging(text)];
  const order={high:0,medium:1,low:2,info:3};
  findings.sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9)||(a.line||0)-(b.line||0));
  return {
    findings,
    summary:{
      high:findings.filter((x)=>x.severity==='high').length,
      medium:findings.filter((x)=>x.severity==='medium').length,
      info:findings.filter((x)=>x.severity==='info').length
    },
    nextActions:[
      ...(findings.some((x)=>x.id==='hf-trust-remote-code'||x.id==='hf-revision-unpinned')?['先固定 model/tokenizer/adapter 的仓库、revision 和 hash，再分析自定义代码与模型文件。']:[]),
      ...(findings.some((x)=>x.id==='unsafe-model-deserialization-call')?['对实际模型文件执行内置 pickle/model 审计，并可交叉运行 ModelScan / PickleScan。']:[]),
      ...(findings.some((x)=>x.id==='python-extra-index'||x.id==='direct-dependency-reference')?['画出 dependency name → source/index → resolved artifact 的解析链，检查同名覆盖和来源漂移。']:[])
    ],
    notes:['供应链 finding 必须结合“攻击者能否影响 artifact/source/revision/path”判断可利用性；未锁版本本身不直接等价于漏洞。']
  };
}

module.exports={ scanPythonSource, scanPackaging, auditAiSupplyChain };
