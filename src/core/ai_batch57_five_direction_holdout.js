'use strict';

const {analyzeTransformExfiltration}=require('./ai_transform_exfiltration');
const {analyzeAdversarialPair}=require('./ai_adversarial');
const {analyzePrivacyTranscript}=require('./ai_privacy');
const {analyzeBackdoorBehavior}=require('./ai_poison_backdoor_validation');
const {auditAiSupplyChain}=require('./ai_supply_chain');

const DIRECTIONS=Object.freeze([
  'prompt-security','adversarial','privacy-leakage','backdoor-poison','supply-chain'
]);
const CASES_PER_DIRECTION=24;
const TOTAL_CASES=DIRECTIONS.length*CASES_PER_DIRECTION;

function encode(text,kind,index){
  const buf=Buffer.from(text,'utf8');
  if(kind==='ascii')return [...buf].join(index%2?' ':',');
  if(kind==='hex')return index%2?buf.toString('hex'):[...buf].map((b)=>`0x${b.toString(16).padStart(2,'0')}`).join(' ');
  if(kind==='base64')return buf.toString('base64');
  if(kind==='url')return [...buf].map((b)=>`%${b.toString(16).padStart(2,'0')}`).join('');
  if(kind==='unicode')return [...text].map((ch)=>`\\u${ch.charCodeAt(0).toString(16).padStart(4,'0')}`).join('');
  throw new Error(`unknown encoding ${kind}`);
}
function promptCases(){
  const kinds=['ascii','hex','base64','url','unicode'];const out=[];
  for(let index=0;index<16;index++){
    const prefix=['vault{','token<','private[','seed('][index%4];const marker=`${prefix}holdout_${index}${prefix.endsWith('{')?'}':prefix.endsWith('<')?'>':prefix.endsWith('[')?']':')'}`;
    out.push({id:`prompt-${index}`,direction:'prompt-security',split:index<8?'canonical':'holdout',expected:'verified',input:{response:`wrapped:${encode(marker,kinds[index%kinds.length],index)}`,protectedTerms:[prefix],maxDepth:3}});
  }
  for(let index=16;index<20;index++){
    const marker=`vault{plain_${index}}`;
    out.push({id:`prompt-${index}`,direction:'prompt-security',split:'holdout',expected:'negative',input:{response:`direct ${marker}`,protectedTerms:['vault{']}});
  }
  for(let index=20;index<24;index++)out.push({id:`prompt-${index}`,direction:'prompt-security',split:'holdout',expected:'negative',input:{response:encode(`ordinary_${index}`,kinds[index%kinds.length],index),protectedTerms:['vault{']}});
  return out;
}
function adversarialCases(){
  const aliases=[
    ['original','adversarial'],['clean','adv'],['x','x_adv'],['x','xAdv']
  ];
  const norms=['linf','l2','l1','l0'];const out=[];
  for(let index=0;index<16;index++){
    const [left,right]=aliases[index%aliases.length],norm=norms[index%norms.length];
    const original=[0.1,0.2,0.3,0.4],adv=original.slice();adv[index%4]+=0.05;
    const epsilon=norm==='l0'?1:0.1;
    const data={[left]:original,[right]:adv,norm,epsilon,trueLabel:0,predictedOriginal:0,predictedAdversarial:1};
    if(index>=8){delete data.trueLabel;data.targetLabel=2;data.predictedAdversarial=2;}
    out.push({id:`adversarial-${index}`,direction:'adversarial',split:index<8?'canonical':'holdout',expected:'within-budget-success',input:data});
  }
  for(let index=16;index<20;index++){
    const norm=norms[index%4],original=[0,0,0,0],adv=[0.4,0,0,0];
    out.push({id:`adversarial-${index}`,direction:'adversarial',split:'holdout',expected:'over-budget',input:{clean:original,adv,norm,epsilon:norm==='l0'?0:0.1,trueLabel:0,predictedAdversarial:1}});
  }
  for(let index=20;index<24;index++)out.push({id:`adversarial-${index}`,direction:'adversarial',split:'holdout',expected:'within-budget-no-success',input:{original:[0,0,0],adversarial:[0.01,0,0],norm:'linf',epsilon:0.1,trueLabel:1,predictedAdversarial:1}});
  return out;
}
function privacyRows(index,strong=true){
  const memberKeys=['member','is_member','split','membership'];const signalFamilies=[
    {key:['confidence','max_confidence','prob','score'][index%4],member:0.94,non:0.12},
    {key:['loss','nll','cross_entropy'][index%3],member:0.08,non:0.92},
    {key:'entropy',member:0.12,non:0.88}
  ];
  const family=signalFamilies[index%signalFamilies.length],memberKey=memberKeys[index%memberKeys.length];const rows=[];
  for(let n=0;n<12;n++){
    const member=n<6;const value=strong?(member?family.member:family.non):(0.48+(n%3)*0.01);
    const label=memberKey==='split'?(member?'train':'test'):member;
    rows.push({[memberKey]:label,[family.key]:value+(strong?(n%2)*0.005:0)});
  }
  if(index%2)rows.reverse();
  return rows;
}
function privacyCases(){
  const out=[];
  for(let index=0;index<16;index++)out.push({id:`privacy-${index}`,direction:'privacy-leakage',split:index<8?'canonical':'holdout',expected:'separation',input:{rows:privacyRows(index,true)}});
  for(let index=16;index<20;index++)out.push({id:`privacy-${index}`,direction:'privacy-leakage',split:'holdout',expected:'weak',input:{rows:privacyRows(index,false)}});
  for(let index=20;index<24;index++)out.push({id:`privacy-${index}`,direction:'privacy-leakage',split:'holdout',expected:'unlabeled',input:{rows:Array.from({length:8},(_,n)=>({score:0.1*n}))}});
  return out;
}
function backdoorRows(index,positive=true,controlSpecific=true){
  const truthKeys=['true_label','label','y_true','ground_truth'];
  const cleanKeys=['clean_pred','original_pred','pred_clean','baseline_pred'];
  const triggerKeys=['triggered_pred','trigger_pred','pred_triggered','backdoor_pred'];
  const controlKeys=['control_pred','neutral_pred','sham_pred'];
  const rows=[];const target='9';
  for(let n=0;n<10;n++){
    const truth=String((n%8)+1);const trigger=positive?target:truth;const control=controlSpecific?truth:target;
    rows.push({[truthKeys[index%truthKeys.length]]:truth,[cleanKeys[index%cleanKeys.length]]:truth,[triggerKeys[index%triggerKeys.length]]:trigger,[controlKeys[index%controlKeys.length]]:control});
  }
  return {target,rows};
}
function backdoorCases(){
  const out=[];
  for(let index=0;index<16;index++){
    const built=backdoorRows(index,true,true);const targetKeys=['targetLabel','target_label','attackTarget','attack_target'];
    out.push({id:`backdoor-${index}`,direction:'backdoor-poison',split:index<8?'canonical':'holdout',expected:'strong',input:{[targetKeys[index%targetKeys.length]]:built.target,rows:built.rows}});
  }
  for(let index=16;index<20;index++){
    const built=backdoorRows(index,false,true);
    out.push({id:`backdoor-${index}`,direction:'backdoor-poison',split:'holdout',expected:'negative',input:{targetLabel:built.target,rows:built.rows}});
  }
  for(let index=20;index<24;index++){
    const built=backdoorRows(index,true,false);
    out.push({id:`backdoor-${index}`,direction:'backdoor-poison',split:'holdout',expected:'non-specific',input:{targetLabel:built.target,rows:built.rows}});
  }
  return out;
}
function supplyCases(){
  const positives=[
    [`model=AutoModel.from_pretrained(name, trust_remote_code=True)`, 'hf-trust-remote-code'],
    [`state=torch.load(path, weights_only=False)`, 'torch-load-weights-only-false'],
    [`obj=pickle.loads(blob)`, 'unsafe-model-deserialization-call'],
    [`subprocess.run(['pip','install',pkg])`, 'runtime-pip-install'],
    [`model=AutoModel.from_pretrained(repo)`, 'hf-revision-unpinned'],
    [`snapshot_download(repo_id=repo)`, 'hf-download-revision-unpinned'],
    [`sys.path.insert(0, os.getcwd())`, 'python-path-shadowing'],
    [`--extra-index-url https://mirror.invalid/simple\ninternal-model>=1`, 'python-extra-index']
  ];
  const out=[];
  for(let index=0;index<16;index++){
    const [source,finding]=positives[index%positives.length];
    out.push({id:`supply-${index}`,direction:'supply-chain',split:index<8?'canonical':'holdout',expected:finding,input:index>=8?`# unrelated header ${index}\n${source}\n# tail`:source});
  }
  const safe=[
    `state=torch.load(path, weights_only=True)`,
    `model=AutoModel.from_pretrained(repo, revision='deadbeef')`,
    `x=np.load(path, allow_pickle=False)`,
    `import os\nprint(os.getcwd())`
  ];
  for(let index=16;index<24;index++)out.push({id:`supply-${index}`,direction:'supply-chain',split:'holdout',expected:'negative',input:safe[index%safe.length]});
  return out;
}
function runCase(item){
  try{
    let pass=false,actual=null;
    if(item.direction==='prompt-security'){
      const result=analyzeTransformExfiltration(item.input);actual=result.verified?'verified':result.candidate?'candidate':'negative';pass=actual===item.expected;
    }else if(item.direction==='adversarial'){
      const result=analyzeAdversarialPair(item.input);actual=result.verdict;pass=actual===item.expected;
    }else if(item.direction==='privacy-leakage'){
      const result=analyzePrivacyTranscript(item.input);
      if(item.expected==='separation'){actual=result.findings.some((x)=>x.id==='membership-separation')?'separation':result.privacyRisk;pass=actual==='separation';}
      else if(item.expected==='unlabeled'){actual=result.findings.some((x)=>x.id==='privacy-groundtruth-missing')?'unlabeled':result.privacyRisk;pass=actual==='unlabeled';}
      else {actual=result.privacyRisk;pass=!['high','medium'].includes(actual);}
    }else if(item.direction==='backdoor-poison'){
      const result=analyzeBackdoorBehavior(item.input);const ids=new Set(result.findings.map((x)=>x.id));
      if(item.expected==='strong'){actual=ids.has('backdoor-target-asr-candidate')&&ids.has('backdoor-control-specificity')?'strong':'other';pass=actual==='strong';}
      else if(item.expected==='non-specific'){actual=ids.has('backdoor-control-specificity')?'specific':'non-specific';pass=actual==='non-specific';}
      else {actual=ids.has('backdoor-target-asr-candidate')?'target-candidate':'negative';pass=actual==='negative';}
    }else if(item.direction==='supply-chain'){
      const result=auditAiSupplyChain(item.input);const ids=new Set(result.findings.map((x)=>x.id));
      actual=item.expected==='negative'?(ids.size?'finding':'negative'):(ids.has(item.expected)?item.expected:'missing');pass=actual===item.expected;
    }
    return {id:item.id,direction:item.direction,split:item.split,expected:item.expected,actual,pass};
  }catch(error){return {id:item.id,direction:item.direction,split:item.split,expected:item.expected,actual:'error',pass:false,error:error?.message||String(error)};}
}
function runBatch57FiveDirectionHoldout(){
  const cases=[...promptCases(),...adversarialCases(),...privacyCases(),...backdoorCases(),...supplyCases()];
  const results=cases.map(runCase);const passed=results.filter((x)=>x.pass).length;
  const directions={};
  for(const direction of DIRECTIONS){
    const rows=results.filter((x)=>x.direction===direction),holdout=rows.filter((x)=>x.split==='holdout');
    directions[direction]={total:rows.length,passed:rows.filter((x)=>x.pass).length,holdoutTotal:holdout.length,holdoutPassed:holdout.filter((x)=>x.pass).length};
  }
  return {
    schema:'newcyber.ai-batch57-five-direction-holdout.v1',batch:57,
    policy:{realCtfCountExcluded:true,noChallengeNames:true,noAnswerMemorization:true,holdoutByRepresentation:true},
    summary:{total:results.length,passed,failed:results.length-passed,passRate:passed/results.length,directions},results
  };
}

module.exports={DIRECTIONS,CASES_PER_DIRECTION,TOTAL_CASES,promptCases,adversarialCases,privacyCases,backdoorCases,supplyCases,runBatch57FiveDirectionHoldout};