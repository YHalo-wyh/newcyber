'use strict';

const fs=require('fs/promises');
const path=require('path');
const {createGpt2Bpe}=require('./gpt2_bpe');

const MAX_LABELS=16384;
const MAX_SOURCE_BYTES=2*1024*1024;
const LABEL_NAMES=[
  'PROFILE_TOKEN_IDS','PROFILING_TOKEN_IDS','TRAIN_TOKEN_IDS','TRAINING_TOKEN_IDS','REFERENCE_TOKEN_IDS','KNOWN_TOKEN_IDS',
  'PROFILE_INPUT_IDS','PROFILING_INPUT_IDS','TRAIN_INPUT_IDS','TRAINING_INPUT_IDS','REFERENCE_INPUT_IDS','KNOWN_INPUT_IDS'
];
const TEXT_NAMES=['PROFILE_TEXT','PROFILING_TEXT','TRAIN_TEXT','TRAINING_TEXT','REFERENCE_TEXT','KNOWN_TEXT'];

function validId(value){return Number.isSafeInteger(Number(value))&&Number(value)>=0;}
function singletonSequences(ids){return ids.map((id)=>[Number(id)]);}
function validateSequences(sequences,expectedTokens,source){
  if(!Array.isArray(sequences)||!sequences.length||sequences.length>MAX_LABELS)return {status:'gap',code:'PROFILE_LABEL_SOURCE_GAP',detail:`${source}: profiling token labels 数量非法`};
  const normalized=[];
  for(const seq of sequences){
    const row=Array.isArray(seq)?seq:[seq];
    if(!row.length||row.length>65536||row.some((id)=>!validId(id)))return {status:'gap',code:'PROFILE_LABEL_SOURCE_GAP',detail:`${source}: profiling token labels 含非法 token id`};
    normalized.push(row.map(Number));
  }
  if(expectedTokens!=null&&Number(expectedTokens)!==normalized.length)return {status:'gap',code:'PROFILE_LABEL_COUNT_GAP',detail:`${source}: labels=${normalized.length}，但 grouped trace 需要 ${expectedTokens} 个 profiling token`};
  return {status:'ok',sequences:normalized,source,count:normalized.length};
}

function sourceConstants(sourceText){
  const out={};
  for(const line of String(sourceText||'').split(/\r?\n/)){
    const m=line.match(/^\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*=\s*(\d+)\s*(?:#.*)?$/);
    if(m)out[m[1]]=Number(m[2]);
  }
  return out;
}

function parseNamedIntegerList(sourceText){
  const text=String(sourceText||'').slice(0,MAX_SOURCE_BYTES);
  for(const name of LABEL_NAMES){
    // Static-only forms: `profile_token_ids=[...]`, `np.array([...])`,
    // `np.asarray([...])`, and `torch.tensor([...])`. We intentionally stop at
    // the closing list bracket, so harmless dtype/device kwargs do not matter.
    const re=new RegExp(`\\b${name}\\s*=\\s*(?:(?:np\\.(?:array|asarray)|torch\\.tensor)\\s*\\(\\s*)?\\[([0-9,\\s]+)\\]`,'mi');
    const m=text.match(re);
    if(!m)continue;
    const ids=m[1].split(',').map((x)=>x.trim()).filter(Boolean).map(Number);
    if(ids.length&&ids.length<=MAX_LABELS&&ids.every(validId))return {ids,source:`source:${name.toLowerCase()}:static-list`,evidence:m[0].slice(0,240)};
  }
  return null;
}

function resolveStaticInteger(token,constants){
  const raw=String(token||'').trim();
  if(/^\d+$/.test(raw))return Number(raw);
  const value=constants[raw];
  return Number.isSafeInteger(value)&&value>=0?value:null;
}

function staticRange(start,stop,step){
  if(!Number.isSafeInteger(start)||!Number.isSafeInteger(stop)||!Number.isSafeInteger(step)||start<0||stop<0||step<=0)return null;
  const ids=[];
  for(let value=start;value<stop;value+=step){
    if(ids.length>=MAX_LABELS)return null;
    ids.push(value);
  }
  return ids.length?ids:null;
}

function parseNamedRange(sourceText){
  const text=String(sourceText||'').slice(0,MAX_SOURCE_BYTES);
  const constants=sourceConstants(text);
  const atom='([A-Za-z_][A-Za-z0-9_]*|\\d+)';
  for(const name of LABEL_NAMES){
    const re=new RegExp(`\\b${name}\\s*=\\s*(?:list\\(\\s*)?(?:np\\.arange|torch\\.arange|range)\\s*\\(\\s*${atom}(?:\\s*,\\s*${atom})?(?:\\s*,\\s*${atom})?\\s*\\)\\s*\\)?`,'mi');
    const m=text.match(re);
    if(!m)continue;
    const args=m.slice(1,4).filter((value)=>value!=null).map((value)=>resolveStaticInteger(value,constants));
    if(args.some((value)=>value==null))continue;
    let start=0,stop,step=1;
    if(args.length===1){stop=args[0];}
    else if(args.length===2){start=args[0];stop=args[1];}
    else if(args.length===3){start=args[0];stop=args[1];step=args[2];}
    else continue;
    const ids=staticRange(start,stop,step);
    if(ids)return {ids,source:`source:${name.toLowerCase()}:static-range`,evidence:m[0].slice(0,240),range:{start,stop,step}};
  }
  return null;
}

function unquoteLiteral(raw){
  const value=String(raw||'');
  if(value.length<2)return null;
  const quote=value[0];
  if(value[value.length-1]!==quote||!['"',"'"].includes(quote))return null;
  const body=value.slice(1,-1);
  if(/\\(?:x|u|U|N\{|[0-7]{1,3})/.test(body))return null;
  return body.replace(/\\n/g,'\n').replace(/\\r/g,'\r').replace(/\\t/g,'\t').replace(/\\([\\'"])/g,'$1');
}

function parseNamedText(sourceText){
  const text=String(sourceText||'').slice(0,MAX_SOURCE_BYTES);
  for(const name of TEXT_NAMES){
    const re=new RegExp(`\\b${name}\\s*=\\s*((?:"(?:[^"\\\\]|\\\\.)*")|(?:'(?:[^'\\\\]|\\\\.)*'))`,'mi');
    const m=text.match(re);if(!m)continue;
    const value=unquoteLiteral(m[1]);if(value!=null)return {text:value,source:`source:${name.toLowerCase()}`,evidence:m[0].slice(0,240)};
  }
  return null;
}

async function tokenizerSibling(modelPath){
  if(!modelPath)return null;
  const dir=path.dirname(modelPath);const vocabPath=path.join(dir,'vocab.json');const mergesPath=path.join(dir,'merges.txt');
  try{
    const vocabStat=await fs.stat(vocabPath);if(!vocabStat.isFile()||vocabStat.size<=0||vocabStat.size>32*1024*1024)return null;
    const vocabText=await fs.readFile(vocabPath,'utf8');let mergesText='';
    try{const mergesStat=await fs.stat(mergesPath);if(mergesStat.isFile()&&mergesStat.size>0&&mergesStat.size<=16*1024*1024)mergesText=await fs.readFile(mergesPath,'utf8');}catch(error){if(error?.code!=='ENOENT')throw error;}
    return {tokenizer:createGpt2Bpe(vocabText,mergesText),vocabPath,mergesPath};
  }catch(error){if(error?.code==='ENOENT')return null;throw error;}
}

async function resolveProfileTokenSequences(discovery,options={}){
  const expectedTokens=options.expectedTokens==null?null:Number(options.expectedTokens);
  const manifest=discovery?.manifest||{};
  const manifestAliases=[
    ['profileTokenSequences',manifest.profileTokenSequences],
    ['profileTokenIdsInline',manifest.profileTokenIdsInline],
    ['profileTokenIds',Array.isArray(manifest.profileTokenIds)?manifest.profileTokenIds:null],
    ['profilingTokenIds',manifest.profilingTokenIds],
    ['trainTokenIds',manifest.trainTokenIds],
    ['trainingTokenIds',manifest.trainingTokenIds],
    ['profileInputIds',manifest.profileInputIds],
    ['profilingInputIds',manifest.profilingInputIds]
  ];
  for(const [key,value] of manifestAliases){
    if(!Array.isArray(value)||!value.length)continue;
    const sequences=Array.isArray(value[0])?value:singletonSequences(value);
    const checked=validateSequences(sequences,expectedTokens,`manifest:${key}`);if(checked.status==='ok')return {...checked,evidence:{kind:'manifest',key}};return checked;
  }

  const role=discovery?.roles?.profileTokenIds;
  if(role?.status==='ok'&&role.file)return {status:'file',file:role.file,source:`file:${role.file.fileName}`};

  const list=parseNamedIntegerList(discovery?.sourceText);if(list){const checked=validateSequences(singletonSequences(list.ids),expectedTokens,list.source);return checked.status==='ok'?{...checked,evidence:{kind:'source-list',text:list.evidence}}:checked;}
  const range=parseNamedRange(discovery?.sourceText);if(range){const checked=validateSequences(singletonSequences(range.ids),expectedTokens,range.source);return checked.status==='ok'?{...checked,evidence:{kind:'source-range',text:range.evidence,range:range.range}}:checked;}

  const text=parseNamedText(discovery?.sourceText);
  if(text){
    const sibling=await tokenizerSibling(options.modelPath);if(!sibling)return {status:'gap',code:'PROFILE_LABEL_TOKENIZER_GAP',detail:`${text.source} 已提供 profiling 明文，但模型同目录没有可证明 tokenizer`};
    let ids;try{ids=sibling.tokenizer.encode(text.text);}catch(error){return {status:'gap',code:'PROFILE_LABEL_TOKENIZER_GAP',detail:`${text.source}: tokenizer 编码失败：${error?.message||String(error)}`};}
    const checked=validateSequences(singletonSequences(ids),expectedTokens,`${text.source}:tokenized`);return checked.status==='ok'?{...checked,evidence:{kind:'source-text',text:text.evidence}}:checked;
  }

  return {
    status:'gap',code:'PROFILE_LABEL_SOURCE_GAP',
    detail:`缺少可证明的 profiling token labels${expectedTokens?`（期望 ${expectedTokens} token）`:''}；不会把 trace 顺序、row index 或 probe index 猜成 token ID。`,
    searched:['manifest profile/profiling/train token or input IDs','profileTokenIds file','static source list / NumPy / Torch tensor','static range/arange with direct integer constants','source profiling text + sibling tokenizer']
  };
}

module.exports={MAX_LABELS,LABEL_NAMES,TEXT_NAMES,parseNamedIntegerList,parseNamedRange,parseNamedText,resolveProfileTokenSequences,validateSequences,sourceConstants,staticRange};