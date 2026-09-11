'use strict';

function text(value){return String(value??'').trim();}
function list(value){return Array.isArray(value)?value.filter(Boolean):[];}
function fileSession(analysis){return analysis?.challengeInput?.kind==='file-session';}
function placement(analysis){
  return fileSession(analysis)
    ?'直接拖到“下一步”卡片，或点“补充材料”；文件会加入当前隔离 Session，随后自动重跑整条分析链。'
    :'把文件放进当前赛题目录（任意子目录都可以），然后点“重新分析”。';
}
function plan(title,why,provide,format,analysis,extra={}){
  return{status:'need-input',title,why,provide:list(provide),format:text(format)||null,where:placement(analysis),action:fileSession(analysis)?'add-files':'rescan',...extra};
}

function membershipPlan(analysis){
  const auto=analysis?.aiMembershipAutopilot;if(!auto||auto.status==='not-detected')return null;
  if(auto.status==='candidate')return plan(
    '补题目判定规则，把 Membership 候选变成可提交结果',
    'Member ID 候选已经自动生成，但没有看到题目要求的提交格式或 checker/scorer，因此不会把候选冒充最终答案。',
    ['checker.py / verifier.py / scorer.py','sample_submission.csv / submission.json','README/题目说明中的评分规则'],
    '只需要能说明“提交哪些字段、顺序、阈值/评分方式”的任一种材料。',analysis,{code:'MEMBERSHIP_VERIFIER_OR_SCHEMA'}
  );
  if(auto.status==='ambiguous')return plan(
    '说明哪份是 calibration，哪份是 query',
    auto.reason||'检测到多个几乎等价的数据配对，自动链拒绝靠文件顺序猜。',
    ['题目 README / description','明确命名的 calibration/reference 文件','明确命名的 query/challenge/test 文件'],
    '推荐命名 calibration.csv 与 query.csv；两边至少共享 loss / confidence / entropy / margin 中一个信号列。',analysis,{code:'MEMBERSHIP_PAIR_AMBIGUOUS'}
  );
  if(auto.status==='gap'){
    const reason=text(auto.reason||auto.next);
    if(/calibration|reference|member\/non-member|真值/i.test(reason))return plan(
      '提供带成员真值的 calibration/reference 数据',reason,
      ['calibration.csv','reference.json / shadow.json'],
      '至少包含 id、member(0/1)；并包含 loss / confidence / entropy / margin 中至少一列。需要同时有 member 与 non-member 样本。',analysis,{code:'MEMBERSHIP_CALIBRATION_MISSING'}
    );
    return plan(
      '提供待判定的 query/challenge 数据',reason,
      ['query.csv','challenge.json / test.csv'],
      '包含 id，以及与 calibration 同名的 loss / confidence / entropy / margin 信号列；不要提供 challenge 真值。',analysis,{code:'MEMBERSHIP_QUERY_MISSING'}
    );
  }
  return null;
}

function onnxPlan(analysis){
  const auto=analysis?.onnxContestAutopilot;if(!auto||auto.status!=='gap')return null;
  const code=text(auto.gap?.code).toUpperCase();const detail=text(auto.gap?.detail);
  if(/MODEL/.test(code)||/onnx model|模型/i.test(detail))return plan('提供唯一可用的 ONNX 模型',detail||'当前没有足够证据自动选择模型。',['*.onnx','模型选择说明 / README'],'如果压缩包里有多个 ONNX，最好同时提供 README/配置指出实际推理模型。',analysis,{code:code||'ONNX_MODEL_MISSING'});
  if(/PREPROCESS|IMAGE|INPUT/.test(code)||/preprocess|resize|normalize|输入/i.test(detail))return plan('提供模型预处理/输入契约',detail||'模型存在，但缺少足够证据安全构造输入。',['infer.py / predict.py / preprocess.py','config.yaml / config.json','示例输入 .npy'],'源码/配置里最好明确 Resize、颜色顺序、Normalize、NCHW/NHWC、dtype；NewCyber 不猜 ImageNet 默认值。',analysis,{code:code||'ONNX_PREPROCESSING_MISSING'});
  if(/HINT|LABEL|CLASS/.test(code)||/hint|label|class|类别/i.test(detail))return plan('提供类别映射或 hint 对',detail||'模型输出存在，但缺少类别/目标映射。',['labels.json / classes.txt','hint.json / challenge config'],'需要能把模型输出下标映射到题目类别，或给出 origin→target 的 hint 对。',analysis,{code:code||'ONNX_LABEL_MAPPING_MISSING'});
  return plan('补齐 ONNX 自动链当前缺口',detail||code||'本地模型自动链缺少一个必要输入。',['题目 README / 配置','模型、预处理、label/hint、示例输入中的缺失项'],'优先把题目原始附件继续丢进来，不要手工改文件内容。',analysis,{code:code||'ONNX_AUTOPILOT_GAP'});
}

function verifierPlan(analysis){
  const verifier=analysis?.verifierContractAutopilot;if(!verifier||verifier.status==='not-applicable'||verifier.status==='verified')return null;
  if(verifier.status==='contracts-found')return plan('提供候选结果对应的原始产物',verifier.next||'checker/verifier 已识别，但当前候选还没有命中判定条件。',['候选输出文件','模型推理结果 / submission 文件'],'保留题目原始格式；NewCyber 会直接按已恢复的 checker contract 复核。',analysis,{code:'VERIFIER_CANDIDATE_MISSING'});
  return null;
}

function primaryNeedPlan(analysis,session){
  const need=session?.primaryNeed;if(!need)return null;
  const accepts=list(need.accepts);const detail=text(need.detail);const title=text(need.title)||'补充当前缺失材料';
  let format=detail;
  const corpus=`${title}\n${need.why||''}\n${detail}`;
  if(/transcript|query|oracle/i.test(corpus))format='CSV/JSON 建议至少包含 query/step、prediction/success/score，以及 distance/epsilon 或题目预算信息。';
  else if(/verifier|checker|scorer|submit/i.test(corpus))format='提供 checker/verifier/scorer 源码、sample submission 或题面中的提交格式说明，任一种即可。';
  else if(/preprocess|resize|normalize|rgb|nchw|nhwc/i.test(corpus))format='提供推理/预处理源码或配置，明确 Resize、颜色通道、Normalize、layout、dtype。';
  return plan(title,text(need.why)||detail||'补齐后自动链会继续执行。',accepts,format,analysis,{code:text(need.code)||'PRIMARY_NEED'});
}

function planChallengeNextInput(analysis={},session={}){
  if(session?.status==='solved')return{status:'complete',title:'结果已验证',why:'当前自动链已经形成可提交闭环。',provide:[],format:null,where:null,action:null,code:'COMPLETE'};
  return membershipPlan(analysis)||onnxPlan(analysis)||verifierPlan(analysis)||primaryNeedPlan(analysis,session)||{
    status:'waiting',title:'暂时不用补材料',why:'NewCyber 已把当前附件能自动执行的步骤跑完；如果题目还有服务端交互或隐藏 checker，请把相关材料继续丢进来。',provide:[],format:null,where:placement(analysis),action:fileSession(analysis)?'add-files':'rescan',code:'NO_EXPLICIT_GAP'
  };
}

module.exports={placement,planChallengeNextInput};
