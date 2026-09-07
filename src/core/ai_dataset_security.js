const { splitCsvLine } = require('./ai_privacy');

function detectDelimiter(header) {
  const candidates=[',','\t',';'];
  return candidates.sort((a,b)=>(header.split(b).length-header.split(a).length))[0];
}

function parseDataset(input) {
  if (input && typeof input==='object') {
    if (Array.isArray(input.rows)) return { rows:input.rows, labelColumn:input.labelColumn||null };
    if (Array.isArray(input)) return { rows:input, labelColumn:null };
  }
  const text=String(input||'').trim();
  if (!text) throw new Error('请输入 CSV/TSV 或 JSON rows');
  if (/^[\[{]/.test(text)) {
    const parsed=JSON.parse(text);
    return { rows:Array.isArray(parsed)?parsed:(parsed.rows||[]), labelColumn:parsed.labelColumn||null };
  }
  const lines=text.split(/\r?\n/).filter((x)=>x.trim());
  if (lines.length<2) throw new Error('数据集至少需要表头和一行数据');
  const delimiter=detectDelimiter(lines[0]);
  const headers=splitCsvLine(lines[0],delimiter);
  const rows=lines.slice(1).map((line,index)=>{
    const values=splitCsvLine(line,delimiter);
    const row={ __row:index+2 };
    headers.forEach((h,i)=>{ row[h]=values[i]??''; });
    return row;
  });
  return { rows, labelColumn:null };
}

function chooseLabelColumn(rows, requested=null) {
  if (requested && rows.some((r)=>Object.prototype.hasOwnProperty.call(r,requested))) return requested;
  const aliases=['label','target','class','y','category','output'];
  const keys=rows[0] ? Object.keys(rows[0]).filter((x)=>!x.startsWith('__')) : [];
  return aliases.find((name)=>keys.some((key)=>key.toLowerCase()===name))
    ? keys.find((key)=>aliases.includes(key.toLowerCase()))
    : null;
}

function stableCell(value) {
  if (value==null) return '';
  if (typeof value==='object') return JSON.stringify(value);
  return String(value).trim();
}

function featureKey(row, columns) {
  return columns.map((key)=>`${key}=${stableCell(row[key])}`).join('\u001f');
}

function tokenise(value) {
  return String(value??'').toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter((x)=>x.length>=3 && x.length<=80);
}

function analyzeDatasetSecurity(input) {
  const parsed=parseDataset(input);
  const rows=parsed.rows.slice(0,20000);
  if (!rows.length) throw new Error('数据集为空');
  const labelColumn=chooseLabelColumn(rows,parsed.labelColumn);
  const columns=Object.keys(rows[0]).filter((x)=>!x.startsWith('__'));
  const featureColumns=columns.filter((x)=>x!==labelColumn);
  const findings=[];

  const exactMap=new Map();
  const featureMap=new Map();
  for (const row of rows) {
    const exact=featureKey(row,columns);
    const exactGroup=exactMap.get(exact)||[]; exactGroup.push(row); exactMap.set(exact,exactGroup);
    if (labelColumn) {
      const key=featureKey(row,featureColumns);
      const group=featureMap.get(key)||[]; group.push(row); featureMap.set(key,group);
    }
  }
  const duplicateGroups=[...exactMap.values()].filter((x)=>x.length>1).map((group)=>({ count:group.length, rows:group.slice(0,20).map((x)=>x.__row??null) })).slice(0,100);
  const conflictingLabels=[];
  if (labelColumn) {
    for (const group of featureMap.values()) {
      if (group.length<2) continue;
      const labels=[...new Set(group.map((row)=>stableCell(row[labelColumn])))];
      if (labels.length>1) conflictingLabels.push({ labels, rows:group.slice(0,20).map((x)=>x.__row??null), sample:Object.fromEntries(featureColumns.slice(0,12).map((k)=>[k,group[0][k]])) });
      if (conflictingLabels.length>=100) break;
    }
  }

  const labelCounts={};
  if (labelColumn) for (const row of rows) labelCounts[stableCell(row[labelColumn])]=(labelCounts[stableCell(row[labelColumn])]||0)+1;
  const labelTotal=Object.values(labelCounts).reduce((a,b)=>a+b,0);
  const rareLabels=Object.entries(labelCounts).filter(([,count])=>labelTotal && count/labelTotal<0.01).map(([label,count])=>({label,count,ratio:count/labelTotal}));

  const tokenStats=new Map();
  if (labelColumn) {
    for (const row of rows) {
      const label=stableCell(row[labelColumn]);
      const seen=new Set();
      for (const col of featureColumns) {
        const value=row[col];
        if (typeof value==='number') continue;
        for (const token of tokenise(value)) seen.add(`${col}\u001e${token}`);
      }
      for (const key of seen) {
        const item=tokenStats.get(key)||{support:0,labels:{}};
        item.support+=1; item.labels[label]=(item.labels[label]||0)+1; tokenStats.set(key,item);
      }
    }
  }
  const triggerCandidates=[];
  for (const [key,item] of tokenStats) {
    if (item.support<2 || item.support>Math.max(40,rows.length*0.1)) continue;
    const [column,token]=key.split('\u001e');
    const top=Object.entries(item.labels).sort((a,b)=>b[1]-a[1])[0];
    if (!top) continue;
    const confidence=top[1]/item.support;
    const prior=(labelCounts[top[0]]||0)/Math.max(labelTotal,1);
    const lift=prior ? confidence/prior : null;
    if (confidence>=0.85 && lift!=null && lift>=1.8) triggerCandidates.push({ column,token,support:item.support,targetLabel:top[0],confidence,lift });
  }
  triggerCandidates.sort((a,b)=>b.lift-a.lift || b.confidence-a.confidence || a.support-b.support);

  if (conflictingLabels.length) findings.push({ id:'dataset-label-conflict', severity:'high', evidence:`groups=${conflictingLabels.length}`, meaning:'相同特征对应多个标签；可能是标注错误、污染或数据拼接问题，应先定位这些行的来源。' });
  if (triggerCandidates.length) findings.push({ id:'dataset-trigger-candidate', severity:'medium', evidence:`candidates=${triggerCandidates.length}`, meaning:'发现低支持度但与特定标签高度绑定的 token/特征值；这是后门/投毒候选，需要做移除、替换和跨样本验证。' });
  if (rareLabels.length) findings.push({ id:'dataset-rare-label', severity:'info', evidence:`rare=${rareLabels.length}`, meaning:'存在极低频标签；先确认是否为合法长尾，再判断是否与异常 token/重复样本共同出现。' });

  return {
    rows:rows.length,
    columns,
    labelColumn,
    labelCounts,
    duplicateGroups,
    conflictingLabels,
    rareLabels,
    triggerCandidates:triggerCandidates.slice(0,80),
    findings,
    notes:[
      'token/标签关联只用于筛选后门候选；高 lift 不等于已存在后门。应通过删除/替换 trigger 后模型输出是否恢复来验证。',
      '图像 patch、频域 trigger 和 clean-label poisoning 需要图像/模型侧证据；本模块先负责数据集结构与可疑共现关系。'
    ]
  };
}

function buildDatasetHarness(input={}) {
  const data=input && typeof input==='object' ? input : {};
  const labelColumn=String(data.labelColumn||'label');
  const cleanlab=`# Cleanlab label-issue harness\n# Requires model out-of-sample predicted probabilities aligned with the dataset.\nimport numpy as np\nfrom cleanlab.filter import find_label_issues\n\nlabels = np.load('labels.npy')\npred_probs = np.load('pred_probs.npy')\nissue_idx = find_label_issues(labels=labels, pred_probs=pred_probs, return_indices_ranked_by='self_confidence')\nprint('candidate_label_issues=', issue_idx[:100].tolist())\n`;
  const backdoor=`# BackdoorBench-compatible investigation plan\n# Dataset label column: ${labelColumn}\n# 1. Export suspicious trigger candidates and their target-label support.\n# 2. Build clean / trigger-inserted / trigger-removed variants.\n# 3. Compare clean accuracy and attack success rate under the challenge model wrapper.\n# 4. Keep patch size/position/frequency perturbation inside the challenge constraints.\n`;
  return {
    harnesses:[
      { backend:'cleanlab', project:'cleanlab/cleanlab', text:cleanlab },
      { backend:'BackdoorBench', project:'SCLBD/BackdoorBench', text:backdoor }
    ]
  };
}

module.exports={ parseDataset, chooseLabelColumn, analyzeDatasetSecurity, buildDatasetHarness };
