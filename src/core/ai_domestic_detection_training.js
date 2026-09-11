'use strict';

const EVENT='2025 gyxxaqjnds Finals';
const SOURCES=Object.freeze({
  adversarial:'https://github.com/CTF-Archives/2025-gyxxaqjnds-Finals/blob/main/%E5%AF%B9%E6%8A%97%E6%A3%80%E6%B5%8B%E9%9D%B6%E5%9C%BA/README.md',
  poisoning:'https://github.com/CTF-Archives/2025-gyxxaqjnds-Finals/blob/main/%E6%8A%95%E6%AF%92%E6%A3%80%E6%B5%8B%E9%9D%B6%E5%9C%BA/README.md',
  deepfake:'https://github.com/CTF-Archives/2025-gyxxaqjnds-Finals/blob/main/%E6%B7%B1%E4%BC%AA%E6%A3%80%E6%B5%8B%E9%9D%B6%E5%9C%BA/README.md'
});

function provenance(title,url){return Object.freeze({title,url,kind:'official-challenge-archive',evidenceLevel:'challenge-source-specific'});}
function seed(meta,fixture){return Object.freeze({trainingPolicy:'synthetic-fixture-only',caseType:'real-ctf',event:EVENT,...meta,provenance:Object.freeze(meta.provenance),fixture:Object.freeze(fixture)});}
function finite(value){const n=Number(value);return Number.isFinite(n)?n:null;}
function clamp01(value){return Math.max(0,Math.min(1,value));}
function binary(value){
  if(value===true||value===1)return 1;
  if(value===false||value===0)return 0;
  const s=String(value??'').trim().toLowerCase();
  if(['1','positive','pos','yes','true','adversarial','poisoned','fake','forged'].includes(s))return 1;
  if(['0','negative','neg','no','false','clean','real','benign'].includes(s))return 0;
  return null;
}
function safeRows(input={}){
  const rows=Array.isArray(input)?input:Array.isArray(input?.rows)?input.rows:[];
  if(rows.length>200000)throw new Error('检测回放最多支持 200000 行');
  return rows;
}
function ratio(num,den){return den?num/den:null;}
function evaluateBinaryDetectionReplay(input={}){
  const rows=safeRows(input);const threshold=finite(input?.threshold);
  let tp=0,tn=0,fp=0,fn=0,invalid=0;const normalized=[];
  for(let i=0;i<rows.length;i+=1){
    const row=rows[i]||{};const truth=binary(row.truth??row.label??row.expected??row.y_true);
    let predicted=binary(row.predicted??row.prediction??row.detected??row.y_pred);
    const score=finite(row.score??row.probability??row.confidence);
    if(predicted==null&&score!=null&&threshold!=null)predicted=score>=threshold?1:0;
    if(truth==null||predicted==null){invalid+=1;continue;}
    if(truth===1&&predicted===1)tp+=1;
    else if(truth===0&&predicted===0)tn+=1;
    else if(truth===0&&predicted===1)fp+=1;
    else fn+=1;
    normalized.push({id:String(row.id??row.file??row.name??`row-${i+1}`),truth,predicted,score});
  }
  const valid=normalized.length;const positives=tp+fn;const negatives=tn+fp;
  const accuracy=ratio(tp+tn,valid);const precision=ratio(tp,tp+fp);const recall=ratio(tp,positives);const specificity=ratio(tn,negatives);
  const f1=precision!=null&&recall!=null&&(precision+recall)>0?2*precision*recall/(precision+recall):null;
  const balancedAccuracy=recall!=null&&specificity!=null?(recall+specificity)/2:null;
  const enough=valid>=4&&positives>0&&negatives>0;
  const strong=enough&&accuracy>=0.8&&(balancedAccuracy==null||balancedAccuracy>=0.75);
  const findings=[];
  if(enough)findings.push({id:'binary-detection-confusion-matrix',severity:'info',title:'二分类检测结果可复算',evidence:`TP=${tp} TN=${tn} FP=${fp} FN=${fn}`,meaning:'当前回放提供 truth 与 predicted，可独立复算检测器指标，避免只相信脚本打印的 accuracy。'});
  if(strong)findings.push({id:'binary-detection-effective-candidate',severity:'medium',title:'检测器在当前回放上达到较高命中率',evidence:`accuracy=${accuracy.toFixed(4)} balanced=${balancedAccuracy?.toFixed(4)??'n/a'}`,meaning:'只代表当前授权/赛题回放上的候选效果；仍需使用题目真实 holdout/scorer 验证。'});
  return{
    schema:'newcyber.binary-detection-replay.v1',rows:rows.length,valid,invalid,threshold,
    confusion:{tp,tn,fp,fn,positives,negatives},
    metrics:{accuracy,precision,recall,specificity,f1,balancedAccuracy},
    verdict:!enough?'insufficient-evidence':strong?'candidate-effective':'candidate-weak',
    findings,preview:normalized.slice(0,128),
    notes:['检测回放只消费已有 truth/prediction 或 score+threshold，不执行题目模型。','候选是否最终有效必须以题目独立 scorer/holdout 为准。']
  };
}
function lossChangeMetric(losses){
  const values=(Array.isArray(losses)?losses:[]).map(Number);
  if(values.length<2||values.some((x)=>!Number.isFinite(x)))return null;
  let abs=0,sq=0;
  for(let i=1;i<values.length;i+=1){const d=values[i]-values[i-1];abs+=Math.abs(d);sq+=d*d;}
  return{steps:values.length-1,meanAbsoluteChange:abs/(values.length-1),rmsChange:Math.sqrt(sq/(values.length-1)),netChange:values[values.length-1]-values[0]};
}
function evaluateLossHistoryPoisonReplay(input={}){
  const rows=safeRows(input);const thresholdRatio=clamp01(finite(input?.thresholdRatio??input?.threshold_ratio)??0.1);
  const ranked=[];
  for(let i=0;i<rows.length;i+=1){
    const row=rows[i]||{};const metric=lossChangeMetric(row.losses??row.lossHistory??row.history);
    if(!metric)continue;
    ranked.push({id:String(row.id??row.file??row.filename??`row-${i+1}`),...metric});
  }
  ranked.sort((a,b)=>b.meanAbsoluteChange-a.meanAbsoluteChange||b.rmsChange-a.rmsChange||a.id.localeCompare(b.id));
  const selectCount=ranked.length?Math.max(1,Math.ceil(ranked.length*thresholdRatio)):0;
  const selected=ranked.slice(0,selectCount);const selectedIds=selected.map((x)=>x.id);
  const truthIds=new Set((Array.isArray(input?.poisonTruth)?input.poisonTruth:[]).map(String));
  let tp=0,fp=0,fn=0;
  if(truthIds.size){
    const selectedSet=new Set(selectedIds);
    for(const id of selectedSet){if(truthIds.has(id))tp+=1;else fp+=1;}
    for(const id of truthIds)if(!selectedSet.has(id))fn+=1;
  }
  const precision=truthIds.size?ratio(tp,tp+fp):null;const recall=truthIds.size?ratio(tp,tp+fn):null;
  const exact=truthIds.size>0&&fp===0&&fn===0&&tp===truthIds.size;
  const findings=[];
  if(ranked.length>=4)findings.push({id:'poison-loss-history-outlier-ranking',severity:'info',title:'按样本 loss 历史变化进行异常排序',evidence:`ranked=${ranked.length}, selected=${selected.length}, thresholdRatio=${thresholdRatio}`,meaning:'复现公开任务描述中的“依据 loss 变化率排序筛选”结构；具体真实算法和阈值仍需按赛题数据校准。'});
  if(exact)findings.push({id:'poison-loss-history-ranking-recovered',severity:'medium',title:'合成回放中 loss 异常排序恢复了投毒集合',evidence:`TP=${tp} FP=${fp} FN=${fn}`,meaning:'该 finding 只用于确定性训练回归，不能推断未知真实数据的投毒标签。'});
  return{
    schema:'newcyber.poison-loss-history-replay.v1',rows:rows.length,rankedRows:ranked.length,thresholdRatio,selectCount,selectedIds,
    validation:truthIds.size?{truth:truthIds.size,tp,fp,fn,precision,recall,exact}:null,
    verdict:ranked.length<4?'insufficient-evidence':exact?'candidate-effective':'ranked',
    findings,ranking:ranked.slice(0,512),
    notes:['公开题面只说明按 loss 变化率排序；这里使用 mean absolute adjacent loss change 作为透明、可复算的合成回归指标，不声称等同原赛题隐藏实现。','真实比赛应在题目给定数据和 scorer 上重新选阈值，不沿用训练 fixture。']
  };
}

function binaryFixture(kind){
  const positives=kind==='deepfake'?['fake-a','fake-b','fake-c','fake-d']:['adv-a','adv-b','adv-c','adv-d'];
  const negatives=kind==='deepfake'?['real-a','real-b','real-c','real-d']:['clean-a','clean-b','clean-c','clean-d'];
  return{rows:[...positives.map((id)=>({id,truth:1,predicted:1})),...negatives.map((id,index)=>({id,truth:0,predicted:index===3?1:0}))]};
}
function poisonFixture(){
  return{thresholdRatio:0.25,poisonTruth:['sample-p1','sample-p2'],rows:[
    {id:'sample-c1',losses:[0.82,0.78,0.75,0.73,0.71]},
    {id:'sample-c2',losses:[0.76,0.73,0.71,0.69,0.68]},
    {id:'sample-c3',losses:[0.91,0.87,0.84,0.82,0.80]},
    {id:'sample-p1',losses:[0.40,1.35,0.32,1.48,0.27]},
    {id:'sample-c4',losses:[0.67,0.64,0.62,0.61,0.60]},
    {id:'sample-c5',losses:[0.88,0.85,0.82,0.80,0.79]},
    {id:'sample-p2',losses:[0.52,1.62,0.41,1.70,0.38]},
    {id:'sample-c6',losses:[0.72,0.70,0.68,0.67,0.66]}
  ]};
}

const DOMESTIC_DETECTION_TRAINING_SEEDS=Object.freeze([
  seed({
    id:'gyxxaqjnds-2025-adversarial-detection',challenge:'对抗检测靶场',direction:'adversarial-example',family:'image-adversarial-detection-scoring',evaluator:'binary-detection',
    provenance:provenance('2025 对抗检测靶场官方归档',SOURCES.adversarial),
    capability:'覆盖批量识别对抗图像、输出逐文件 0/1 CSV、按 TP/TN 等独立 scorer 复算的检测型 AI 赛题；不保存原数据集或模型。'
  },binaryFixture('adversarial')),
  seed({
    id:'gyxxaqjnds-2025-poison-detection',challenge:'投毒检测靶场',direction:'backdoor-poisoning',family:'loss-history-poison-ranking',evaluator:'loss-history-poison',
    provenance:provenance('2025 投毒检测靶场官方归档',SOURCES.poisoning),
    capability:'覆盖基于每样本 loss 历史变化进行异常排序、按阈值比例筛出投毒样本并输出 0/1 结果的题型。'
  },poisonFixture()),
  seed({
    id:'gyxxaqjnds-2025-deepfake-detection',challenge:'深伪检测靶场',direction:'multimodal-ai',family:'xception-deepfake-detection',evaluator:'binary-detection',
    provenance:provenance('2025 深伪检测靶场官方归档',SOURCES.deepfake),
    capability:'覆盖补全/审计深伪检测 pipeline 后，对图像 real/fake 结果做独立 confusion-matrix 与 accuracy/F1 复算；不加载归档中的不受信模型权重。'
  },binaryFixture('deepfake'))
]);

function clone(value){return JSON.parse(JSON.stringify(value));}
function negativeFixture(item){
  const fixture=clone(item.fixture);
  if(item.evaluator==='binary-detection'){
    fixture.rows=fixture.rows.map((row)=>({...row,predicted:Number(row.truth)===1?0:1}));
    return fixture;
  }
  if(item.evaluator==='loss-history-poison'){
    fixture.rows=fixture.rows.map((row,index)=>({...row,losses:[0.8-index*0.01,0.78-index*0.01,0.76-index*0.01,0.74-index*0.01,0.72-index*0.01]}));
    return fixture;
  }
  return fixture;
}
function execute(item,fixture){
  if(item.evaluator==='binary-detection')return evaluateBinaryDetectionReplay(fixture);
  if(item.evaluator==='loss-history-poison')return evaluateLossHistoryPoisonReplay(fixture);
  throw new Error(`unsupported domestic detection evaluator ${item.evaluator}`);
}
function positivePassed(item,result){
  if(item.evaluator==='binary-detection')return result?.verdict==='candidate-effective'&&(result?.findings||[]).some((x)=>x.id==='binary-detection-effective-candidate');
  if(item.evaluator==='loss-history-poison')return result?.validation?.exact===true&&(result?.findings||[]).some((x)=>x.id==='poison-loss-history-ranking-recovered');
  return false;
}
function negativePassed(item,result){
  if(item.evaluator==='binary-detection')return result?.verdict!=='candidate-effective'&&!(result?.findings||[]).some((x)=>x.id==='binary-detection-effective-candidate');
  if(item.evaluator==='loss-history-poison')return result?.validation?.exact===false&&!(result?.findings||[]).some((x)=>x.id==='poison-loss-history-ranking-recovered');
  return false;
}
function metadata(item){return{id:item.id,event:item.event,challenge:item.challenge,caseType:item.caseType,direction:item.direction,family:item.family,evaluator:item.evaluator,trainingPolicy:item.trainingPolicy,provenance:{...item.provenance},capability:item.capability};}
function getDomesticDetectionTrainingCorpus(){return DOMESTIC_DETECTION_TRAINING_SEEDS.map(metadata);}
function runDomesticDetectionTrainingRegression(options={}){
  const variants=Math.max(1,Math.min(8,Number(options.variantsPerSeed)||3));const results=[];
  for(const item of DOMESTIC_DETECTION_TRAINING_SEEDS){
    for(let index=0;index<variants;index+=1){
      for(const control of ['positive','negative']){
        let output;try{output=execute(item,control==='positive'?clone(item.fixture):negativeFixture(item));}
        catch(error){output={error:error?.message||String(error),findings:[]};}
        const ok=!output.error&&(control==='positive'?positivePassed(item,output):negativePassed(item,output));
        results.push({seed:item.id,event:item.event,challenge:item.challenge,direction:item.direction,family:item.family,evaluator:item.evaluator,variant:index,control,status:output.error?'error':ok?'pass':'miss',findingIds:(output.findings||[]).map((x)=>x.id),error:output.error||null,provenance:{...item.provenance}});
      }
    }
  }
  const pass=results.filter((x)=>x.status==='pass').length;
  return{schema:'newcyber.domestic-ai-detection-training.v1',summary:{seeds:DOMESTIC_DETECTION_TRAINING_SEEDS.length,cases:results.length,pass,miss:results.filter((x)=>x.status==='miss').length,error:results.filter((x)=>x.status==='error').length,passRate:results.length?pass/results.length:0,families:new Set(DOMESTIC_DETECTION_TRAINING_SEEDS.map((x)=>x.family)).size},results,note:'来自官方公开赛题归档的机制只用于 deterministic synthetic regression；不执行归档中的 .pt/.pth，不复制真实数据集，也不把训练 fixture 阈值当作比赛答案。'};
}

module.exports={EVENT,SOURCES,DOMESTIC_DETECTION_TRAINING_SEEDS,binary,lossChangeMetric,evaluateBinaryDetectionReplay,evaluateLossHistoryPoisonReplay,getDomesticDetectionTrainingCorpus,runDomesticDetectionTrainingRegression};
