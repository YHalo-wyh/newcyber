'use strict';

const {analyzeAdversarialPair}=require('./ai_adversarial');
const {analyzeModelExtractionTranscript}=require('./ai_model_extraction');
const {analyzeModelInversion}=require('./ai_model_inversion');

const EVENTS=Object.freeze({
  dc30:'AI Village CTF @ DEFCON 30',
  dc31:'AI Village CTF @ DEFCON 31'
});
const SOURCES=Object.freeze({
  dc30:'https://github.com/IsaiahPressman/ai_village_ctf_30/blob/main/README.md',
  dc31:'https://github.com/conor-99/AI-Village-CTF-DEFCON-31/blob/main/README.md'
});

function provenance(eventKey,challenge){
  return Object.freeze({
    title:`${EVENTS[eventKey]} participant writeup — ${challenge}`,
    url:SOURCES[eventKey],kind:'ctf-writeup',evidenceLevel:'writeup-specific'
  });
}
function seed(eventKey,meta,fixture){
  return Object.freeze({
    trainingPolicy:'synthetic-fixture-only',event:EVENTS[eventKey],caseType:'real-ctf',
    ...meta,provenance:provenance(eventKey,meta.challenge),fixture:Object.freeze(fixture)
  });
}
function adversarialFixture(targeted=true){
  return {
    original:[0.12,0.28,0.44,0.61,0.79],
    adversarial:[0.13,0.27,0.45,0.60,0.80],
    norm:'linf',epsilon:0.02,clip:[0,1],
    trueLabel:'clean',predictedOriginal:'clean',predictedAdversarial:targeted?'target':'other',
    ...(targeted?{targetLabel:'target'}:{})
  };
}
function extractionFixture(){
  return [
    {query:'probe-a',label:'A',probabilities:[0.91234567,0.08765433]},
    {query:'probe-a',label:'A',probabilities:[0.91234567,0.08765433]},
    {query:'probe-b',label:'B',probabilities:[0.23123456,0.76876544]},
    {query:'probe-b',label:'B',probabilities:[0.23123456,0.76876544]},
    {query:'probe-c',label:'A',probabilities:[0.63456789,0.36543211]},
    {query:'probe-c',label:'A',probabilities:[0.63456789,0.36543211]}
  ];
}
function inversionFixture(){
  return {rows:[
    {reference:[0.80,0.10,0.05,0.05],reconstructed:[0.79,0.11,0.05,0.05]},
    {reference:[0.05,0.10,0.80,0.05],reconstructed:[0.05,0.11,0.79,0.05]}
  ]};
}

const AIVILLAGE_TRAINING_SEEDS=Object.freeze([
  seed('dc30',{
    id:'aiv-dc30-honor-student',challenge:'Honor Student',direction:'adversarial-example',family:'tamper-detector-compression-bypass',evaluator:'adversarial',
    capability:'覆盖图像分类目标已满足但还需绕过独立 tamper 检测的双约束题型；训练只验证合成扰动预算与目标输出，不保存原提交图。'
  },adversarialFixture()),
  seed('dc30',{
    id:'aiv-dc30-wifi',challenge:'Wifi',direction:'privacy-leakage',family:'manifold-projection-token-recovery',evaluator:'structured',
    capability:'覆盖高维表示经流形降维后显露字符/令牌顺序的表示泄露题型。'
  },{riskType:'manifold-token-recovery',embeddingProjectionAvailable:true,tokenMetadataAligned:true,lowDimensionalStructureVisible:true,hiddenSequenceRecovered:true}),
  seed('dc30',{
    id:'aiv-dc30-bad-to-good',challenge:'Bad to Good',direction:'dataset-pipeline-security',family:'tabular-counterfactual-boundary-search',evaluator:'structured',
    capability:'覆盖结构化特征允许越界/异常取值时，通过 counterfactual 搜索跨越模型边界的题型。'
  },{riskType:'tabular-counterfactual-boundary-search',editableFeatures:true,outOfDistributionValuesAccepted:true,scoreOrDecisionOracle:true,targetDecisionReached:true}),
  seed('dc30',{
    id:'aiv-dc30-baseball',challenge:'Baseball',direction:'model-extraction',family:'confidence-oracle-black-box-search',evaluator:'extraction',
    capability:'覆盖黑盒服务返回稳定高精度置信度，进而可用于网格搜索/局部采样逼近高分区域的题型。'
  },extractionFixture()),
  seed('dc30',{
    id:'aiv-dc30-inference',challenge:'Inference',direction:'model-extraction',family:'character-oracle-topk-reconstruction',evaluator:'extraction',
    capability:'覆盖字符分类器被逐字符探测、利用 soft-label/top-k 候选重建隐藏序列的黑盒抽取题型。'
  },extractionFixture()),
  seed('dc30',{
    id:'aiv-dc30-leakage',challenge:'Leakage',direction:'privacy-leakage',family:'sequence-model-context-leak',evaluator:'structured',
    capability:'覆盖序列模型把与输入标识符相关的敏感上下文直接回吐的记忆/上下文泄露。'
  },{riskType:'sequence-model-context-leak',identifierInputAccepted:true,sensitiveSequenceReturned:true,independentAuthorizationAbsent:true,leakageObserved:true}),
  seed('dc30',{
    id:'aiv-dc30-forensics',challenge:'Forensics',direction:'infra-supply-chain',family:'model-introspection-sensitive-metadata',evaluator:'structured',
    capability:'覆盖仅通过模型结构/summary/metadata 即可恢复敏感线索的模型工件取证题型，强调优先静态审计。'
  },{riskType:'model-introspection-sensitive-metadata',modelIntrospectionAvailable:true,sensitiveMetadataInGraph:true,secretMarkerRecovered:true,artifactExecutionNotRequired:true}),
  seed('dc30',{
    id:'aiv-dc30-token',challenge:'Token',direction:'dataset-pipeline-security',family:'dataset-marker-forensics',evaluator:'structured',
    capability:'覆盖原始数据尾部/异常行存在重复 marker，通过数据取证而非训练模型定位关键记录。'
  },{riskType:'dataset-marker-forensics',rawDatasetAvailable:true,repeatedMarkersDetected:true,anomalousRowsIsolated:true,hiddenRecordRecovered:true}),
  seed('dc30',{
    id:'aiv-dc30-deepfake',challenge:'Deepfake',direction:'multimodal-ai',family:'media-track-semantic-bypass',evaluator:'structured',
    capability:'覆盖多模态验证只检查某一路媒体内容，替换视频轨/静态帧即可满足语义目标的 verifier 边界。'
  },{riskType:'media-track-semantic-bypass',multimodalVerifier:true,replaceableMediaTrack:true,semanticCheckBypassed:true,serverVerifierAccepted:true}),
  seed('dc30',{
    id:'aiv-dc30-murderbots',challenge:'Murderbots',direction:'model-extraction',family:'local-surrogate-ranking',evaluator:'structured',
    capability:'覆盖根据公开训练数据拟合轻量替代模型，再按 surrogate score 对候选进行排名的赛题结构。'
  },{riskType:'local-surrogate-ranking',trainingDataAvailable:true,surrogateFitOffline:true,candidateScoresProduced:true,topCandidatesValidated:true}),
  seed('dc30',{
    id:'aiv-dc30-hotterdog',challenge:'Hotterdog',direction:'adversarial-example',family:'black-box-transfer-adversarial',evaluator:'adversarial',
    capability:'覆盖目标模型未知时，基于开源 surrogate/transfer attack 与可见目标叠加构造黑盒对抗候选。'
  },adversarialFixture()),
  seed('dc30',{
    id:'aiv-dc30-theft',challenge:'Theft',direction:'adversarial-example',family:'white-box-adversarial-example',evaluator:'adversarial',
    capability:'覆盖题目直接提供模型时，在已知预处理与扰动约束内构造 white-box 对抗样本。'
  },adversarialFixture()),
  seed('dc30',{
    id:'aiv-dc30-salt',challenge:'Salt',direction:'adversarial-example',family:'white-box-adversarial-example',evaluator:'adversarial',
    capability:'覆盖已知模型与约束下的目标/非目标对抗样本验证，强调 verifier preprocessing 对齐。'
  },adversarialFixture(false)),
  seed('dc30',{
    id:'aiv-dc30-crop1',challenge:'Crop_1',direction:'adversarial-example',family:'preprocessing-crop-assumption-bypass',evaluator:'structured',
    capability:'覆盖服务端裁剪/尺寸假设与允许输入尺寸不一致时，通过 alternate resolution 构造裁剪不变候选。'
  },{riskType:'preprocessing-crop-assumption-bypass',fixedCropAssumption:true,alternateResolutionAccepted:true,transformationInvariantCandidate:true,targetDecisionReached:true}),
  seed('dc30',{
    id:'aiv-dc30-waf',challenge:'WAF',direction:'model-extraction',family:'decision-oracle-substring-recovery',evaluator:'structured',
    capability:'覆盖仅有布尔检测反馈时，通过固定窗口逐字符扩展恢复触发模式，再变形绕过检测的 decision-oracle 题型。'
  },{riskType:'decision-oracle-substring-recovery',booleanOracle:true,prefixExtensionSearch:true,bidirectionalRecovery:true,payloadStructureRecovered:true}),
  seed('dc30',{
    id:'aiv-dc30-secret-sloth',challenge:'Secret Sloth',direction:'model-extraction',family:'dictionary-semantic-oracle-search',evaluator:'structured',
    capability:'覆盖有限词典对语义/分类 oracle 的批量探测与候选排序；训练记录搜索结构，不保存原答案。'
  },{riskType:'dictionary-semantic-oracle-search',boundedDictionary:true,scoreOrDecisionOracle:true,candidatesRanked:true,targetCandidateValidated:true}),

  seed('dc31',{
    id:'aiv-dc31-cluster-l1',challenge:'Cluster - Level 1',direction:'dataset-pipeline-security',family:'misclassification-subset-hillclimb',evaluator:'structured',
    capability:'覆盖先定位特定误分类子集，再在类别/字段约束下做 score-guided hill climbing 的结构化模型题。'
  },{riskType:'misclassification-subset-hillclimb',misclassifiedSubsetIdentified:true,categoryConstraintApplied:true,scoreGuidedHillClimb:true,targetDecisionReached:true}),
  seed('dc31',{
    id:'aiv-dc31-cluster-l3',challenge:'Cluster - Level 3',direction:'privacy-leakage',family:'embedding-cluster-token-overlay',evaluator:'structured',
    capability:'覆盖高维 embedding 通过 t-SNE 等降维并叠加 token 元数据后恢复潜在序列/结构。'
  },{riskType:'embedding-cluster-token-overlay',highDimensionalVectors:true,dimensionalityReductionUsed:true,tokenLabelsAvailable:true,latentSequenceRecovered:true}),
  seed('dc31',{
    id:'aiv-dc31-granny-l2',challenge:'Granny - Level 2',direction:'adversarial-example',family:'black-box-genetic-adversarial',evaluator:'adversarial',
    capability:'覆盖没有梯度时，使用 genetic/evolutionary search 只依赖模型输出构造图像对抗候选。'
  },adversarialFixture()),
  seed('dc31',{
    id:'aiv-dc31-passphrase',challenge:'Passphrase',direction:'model-extraction',family:'constrained-surrogate-hillclimb',evaluator:'structured',
    capability:'覆盖使用本地 surrogate 对满足词长/词典约束的候选做 hill climbing，并由远端 verifier 最终确认。'
  },{riskType:'constrained-surrogate-hillclimb',localSurrogateAvailable:true,lexicalConstraintsApplied:true,scoreGuidedSearch:true,serverVerifierAccepted:true}),
  seed('dc31',{
    id:'aiv-dc31-pixelated',challenge:'Pixelated',direction:'multimodal-ai',family:'ocr-to-markup-parser-boundary',evaluator:'structured',
    capability:'覆盖图像中的文本先被 OCR 恢复，再被下游 XML/markup 解析器解释，形成跨模态 parser boundary 的题型。'
  },{riskType:'ocr-to-markup-parser-boundary',imageCarriesMarkupText:true,ocrRecoveredPayload:true,downstreamParserInterpreted:true,serverVerifierAccepted:true}),
  seed('dc31',{
    id:'aiv-dc31-semantle-l2',challenge:'Semantle - Level 2',direction:'model-extraction',family:'similarity-oracle-lexicon-search',evaluator:'structured',
    capability:'覆盖大词表批量查询 similarity oracle、按分数缩小候选再组合搜索的 embedding 黑盒题。'
  },{riskType:'similarity-oracle-lexicon-search',semanticScoreOracle:true,largeCandidateLexicon:true,shortlistSearch:true,targetCandidateValidated:true}),
  seed('dc31',{
    id:'aiv-dc31-inversion',challenge:'Inversion',direction:'privacy-leakage',family:'probability-guided-model-inversion',evaluator:'inversion',
    capability:'覆盖从概率/输出统计恢复输入字符或代表性样本，并用独立相似度指标验证 reconstruction。'
  },inversionFixture()),
  seed('dc31',{
    id:'aiv-dc31-guess-whos-back',challenge:"Guess Who's Back?",direction:'privacy-leakage',family:'range-clipping-image-reconstruction',evaluator:'structured',
    capability:'覆盖通过逐步收紧数值 clip 范围让被隐藏的图像结构显现，属于数值表示泄露/重建题型。'
  },{riskType:'range-clipping-image-reconstruction',boundedPixelRange:true,iterativeRangeTightening:true,imageStructureEmerged:true,reconstructionValidated:true}),
  seed('dc31',{
    id:'aiv-dc31-count-mnist',challenge:'Count MNIST',direction:'dataset-pipeline-security',family:'metadata-coded-counting',evaluator:'structured',
    capability:'覆盖类别/颜色等元数据已经直接编码答案结构时，优先做统计与 schema 审计而非无意义训练。'
  },{riskType:'metadata-coded-counting',metadataColumnEncodesGroup:true,countsDerivedDirectly:true,modelTrainingNotRequired:true,serverVerifierAccepted:true})
]);

const STRUCTURED_RULES=Object.freeze({
  'manifold-token-recovery':['embeddingProjectionAvailable','tokenMetadataAligned','lowDimensionalStructureVisible','hiddenSequenceRecovered'],
  'tabular-counterfactual-boundary-search':['editableFeatures','outOfDistributionValuesAccepted','scoreOrDecisionOracle','targetDecisionReached'],
  'sequence-model-context-leak':['identifierInputAccepted','sensitiveSequenceReturned','independentAuthorizationAbsent','leakageObserved'],
  'model-introspection-sensitive-metadata':['modelIntrospectionAvailable','sensitiveMetadataInGraph','secretMarkerRecovered','artifactExecutionNotRequired'],
  'dataset-marker-forensics':['rawDatasetAvailable','repeatedMarkersDetected','anomalousRowsIsolated','hiddenRecordRecovered'],
  'media-track-semantic-bypass':['multimodalVerifier','replaceableMediaTrack','semanticCheckBypassed','serverVerifierAccepted'],
  'local-surrogate-ranking':['trainingDataAvailable','surrogateFitOffline','candidateScoresProduced','topCandidatesValidated'],
  'preprocessing-crop-assumption-bypass':['fixedCropAssumption','alternateResolutionAccepted','transformationInvariantCandidate','targetDecisionReached'],
  'decision-oracle-substring-recovery':['booleanOracle','prefixExtensionSearch','bidirectionalRecovery','payloadStructureRecovered'],
  'dictionary-semantic-oracle-search':['boundedDictionary','scoreOrDecisionOracle','candidatesRanked','targetCandidateValidated'],
  'misclassification-subset-hillclimb':['misclassifiedSubsetIdentified','categoryConstraintApplied','scoreGuidedHillClimb','targetDecisionReached'],
  'embedding-cluster-token-overlay':['highDimensionalVectors','dimensionalityReductionUsed','tokenLabelsAvailable','latentSequenceRecovered'],
  'constrained-surrogate-hillclimb':['localSurrogateAvailable','lexicalConstraintsApplied','scoreGuidedSearch','serverVerifierAccepted'],
  'ocr-to-markup-parser-boundary':['imageCarriesMarkupText','ocrRecoveredPayload','downstreamParserInterpreted','serverVerifierAccepted'],
  'similarity-oracle-lexicon-search':['semanticScoreOracle','largeCandidateLexicon','shortlistSearch','targetCandidateValidated'],
  'range-clipping-image-reconstruction':['boundedPixelRange','iterativeRangeTightening','imageStructureEmerged','reconstructionValidated'],
  'metadata-coded-counting':['metadataColumnEncodesGroup','countsDerivedDirectly','modelTrainingNotRequired','serverVerifierAccepted']
});

function clone(value){return JSON.parse(JSON.stringify(value));}
function evaluateStructuredReplay(input={}){
  const riskType=String(input.riskType||'');const required=STRUCTURED_RULES[riskType];
  if(!required)return{verdict:'error',findings:[],error:`unsupported AI Village replay ${riskType}`};
  const matched=required.filter((key)=>input[key]===true);const hit=matched.length===required.length;
  return{
    verdict:hit?'candidate-failure':'no-explicit-failure',
    signals:{riskType,required:required.length,matched:matched.length},
    findings:hit?[{id:`aivillage-${riskType}`,severity:'medium',title:`AI Village 训练回放命中 ${riskType}`,evidence:'synthetic challenge-derived evidence',meaning:'只证明 NewCyber 能识别公开题解抽象出的机制，不代表自动复现原比赛服务或原提交。'}]:[],
    notes:['synthetic fixture 不保存原题 Flag、口令、候选字符串、图像、exact perturbation 或 winning parameter。']
  };
}
function positiveFixture(item,index){
  const fixture=clone(item.fixture);
  if(item.evaluator==='structured')fixture.observationId=`aivillage-synthetic-${index}`;
  if(item.evaluator==='adversarial')fixture.sampleId=`aivillage-adv-${index}`;
  if(item.evaluator==='extraction'&&Array.isArray(fixture))fixture.forEach((row,i)=>{row.timestamp=`synthetic-${index}-${i}`;});
  return fixture;
}
function negativeFixture(item){
  const fixture=clone(item.fixture);
  if(item.evaluator==='structured'){
    const required=STRUCTURED_RULES[fixture.riskType]||[];
    if(required.length)fixture[required[0]]=false;
    return fixture;
  }
  if(item.evaluator==='adversarial'){
    fixture.adversarial=clone(fixture.original);
    fixture.predictedAdversarial=fixture.trueLabel||fixture.predictedOriginal;
    delete fixture.targetLabel;
    return fixture;
  }
  if(item.evaluator==='extraction')return [
    {query:'negative-a',label:'A'},{query:'negative-b',label:'B'},{query:'negative-c',label:'A'}
  ];
  if(item.evaluator==='inversion')return {rows:[{reference:[1,0,0,0],reconstructed:[0,1,0,0]}]};
  return fixture;
}
function execute(item,fixture){
  if(item.evaluator==='structured')return evaluateStructuredReplay(fixture);
  if(item.evaluator==='adversarial')return analyzeAdversarialPair(fixture);
  if(item.evaluator==='extraction')return analyzeModelExtractionTranscript(fixture);
  if(item.evaluator==='inversion')return analyzeModelInversion(fixture);
  throw new Error(`unsupported AI Village evaluator ${item.evaluator}`);
}
function positivePassed(item,result){
  if(item.evaluator==='structured')return result?.verdict==='candidate-failure';
  if(item.evaluator==='adversarial')return result?.verdict==='within-budget-success'&&(result?.findings||[]).some((x)=>x.id==='adversarial-candidate-valid');
  if(item.evaluator==='extraction')return (result?.findings||[]).some((x)=>x.id==='extraction-full-probability-output')&&result?.extractionExposure!=='limited';
  if(item.evaluator==='inversion')return (result?.findings||[]).some((x)=>x.id==='inversion-reconstruction-similarity');
  return false;
}
function negativePassed(item,result){
  if(item.evaluator==='structured')return result?.verdict==='no-explicit-failure'&&!(result?.findings||[]).length;
  if(item.evaluator==='adversarial')return result?.verdict!=='within-budget-success'&&!(result?.findings||[]).some((x)=>x.id==='adversarial-candidate-valid');
  if(item.evaluator==='extraction')return !(result?.findings||[]).some((x)=>['extraction-full-probability-output','extraction-score-vector-output'].includes(x.id));
  if(item.evaluator==='inversion')return !(result?.findings||[]).some((x)=>x.id==='inversion-reconstruction-similarity');
  return false;
}
function metadata(item){
  return {id:item.id,event:item.event,challenge:item.challenge,caseType:item.caseType,direction:item.direction,family:item.family,evaluator:item.evaluator,trainingPolicy:item.trainingPolicy,provenance:{...item.provenance},capability:item.capability};
}
function getAiVillageTrainingCorpus(){return AIVILLAGE_TRAINING_SEEDS.map(metadata);}
function runAiVillageTrainingRegression(options={}){
  const variants=Math.max(1,Math.min(8,Number(options.variantsPerSeed)||3));const results=[];
  for(const item of AIVILLAGE_TRAINING_SEEDS){
    for(let index=0;index<variants;index+=1){
      for(const control of ['positive','negative']){
        let output;try{output=execute(item,control==='positive'?positiveFixture(item,index):negativeFixture(item));}
        catch(error){output={error:error?.message||String(error)};}
        const ok=!output.error&&(control==='positive'?positivePassed(item,output):negativePassed(item,output));
        results.push({seed:item.id,event:item.event,challenge:item.challenge,direction:item.direction,family:item.family,evaluator:item.evaluator,variant:index,control,status:output.error?'error':ok?'pass':'miss',findingIds:(output.findings||[]).map((x)=>x.id),error:output.error||null,provenance:{...item.provenance}});
      }
    }
  }
  const pass=results.filter((x)=>x.status==='pass').length;
  return {
    schema:'newcyber.aivillage-training.v1',
    summary:{seeds:AIVILLAGE_TRAINING_SEEDS.length,cases:results.length,pass,miss:results.filter((x)=>x.status==='miss').length,error:results.filter((x)=>x.status==='error').length,passRate:results.length?pass/results.length:0,events:new Set(AIVILLAGE_TRAINING_SEEDS.map((x)=>x.event)).size,challenges:new Set(AIVILLAGE_TRAINING_SEEDS.map((x)=>x.challenge)).size,families:new Set(AIVILLAGE_TRAINING_SEEDS.map((x)=>x.family)).size},
    results,
    note:'AI Village DEFCON 30/31 participant writeups are used only for challenge mechanics/provenance. Executable replays are synthetic with explicit negative controls and omit original answers, images, strings and winning parameters.'
  };
}

module.exports={EVENTS,SOURCES,STRUCTURED_RULES,AIVILLAGE_TRAINING_SEEDS,evaluateStructuredReplay,getAiVillageTrainingCorpus,runAiVillageTrainingRegression};
