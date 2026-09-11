'use strict';

const fs=require('fs/promises');
const path=require('path');
const {inspectOnnxModel}=require('./local_ml_runtime');
const {resolveModelInputPlan,inputPlanView}=require('./challenge_onnx_input_bindings');

const MAX_MODEL_BYTES=2*1024*1024*1024;
const MAX_MODELS=12;

function list(value){return Array.isArray(value)?value:[];}
function inside(root,target){const rel=path.relative(path.resolve(root),path.resolve(target));return rel===''||(!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel));}
function staticDim(value){const n=Number(value);return Number.isInteger(n)&&n>0?n:null;}
function modelFiles(analysis){return list(analysis?.files).filter((file)=>String(file.extension||path.extname(file.path||'')).toLowerCase()==='.onnx');}
function compatibleDims(actual,expected){if(!Array.isArray(actual)||!Array.isArray(expected)||actual.length!==expected.length)return false;return actual.every((value,index)=>{const a=staticDim(value),e=staticDim(expected[index]);return a===null||e===null||a===e;});}
function fixedMismatch(actual,expected){if(!Array.isArray(actual)||!Array.isArray(expected)||actual.length!==expected.length)return true;return actual.some((value,index)=>{const a=staticDim(value),e=staticDim(expected[index]);return a!==null&&e!==null&&a!==e;});}
function compatibleWithOptionalBatch(actual,expected){
  if(compatibleDims(actual,expected))return{compatible:true,adaptation:'exact'};
  if(Array.isArray(actual)&&Array.isArray(expected)&&expected.length===actual.length+1){const first=staticDim(expected[0]),expanded=[1,...actual];if((first===null||first===1)&&compatibleDims(expanded,expected))return{compatible:true,adaptation:'prepend-batch-1'};}
  return{compatible:false,adaptation:null};
}

function expectedImageDims(manifest){
  const p=manifest?.pipeline||{};const spatial=p.crop&&p.crop.type==='center'?p.crop:p.size;if(!spatial)return null;
  const color=String(p.color||'').toUpperCase();let channels=color==='GRAY'?1:(color==='RGB'||color==='BGR'?3:null);
  if(channels===null&&p.shape?.dims){const dims=p.shape.dims,layout=String(p.shape.layout||p.layout||'').toUpperCase();if(layout==='NCHW')channels=staticDim(dims[1]);else if(layout==='NHWC')channels=staticDim(dims[3]);else if(layout==='CHW')channels=staticDim(dims[0]);else if(layout==='HWC')channels=staticDim(dims[2]);}
  if(!channels)return null;const h=Number(spatial.height),w=Number(spatial.width);if(!Number.isInteger(h)||!Number.isInteger(w))return null;
  const layout=String(p.layout||'').toUpperCase();let dims;if(layout==='CHW'||layout==='NCHW')dims=[channels,h,w];else if(layout==='HWC'||layout==='NHWC')dims=[h,w,channels];else return null;
  if(layout.startsWith('N')||p.batch==='prepend-axis')dims=[1,...dims];return dims;
}

function vectorOutputScore(model){
  let best=0;for(const output of list(model?.outputs)){const dims=output?.metadata?.dimensions;if(!Array.isArray(dims))continue;
    if(dims.length===1){const c=staticDim(dims[0]);if(c===null||c>=2)best=Math.max(best,4);}
    else if(dims.length===2){const n=staticDim(dims[0]),c=staticDim(dims[1]);if((n===null||n===1)&&(c===null||c>=2))best=Math.max(best,4);}
  }return best;
}
function scoreExplicit(model,bundle){
  const candidate=bundle?.candidates?.[0];if(!candidate?.feeds)return{score:0,reasons:[],inputPlan:null};const names=Object.keys(candidate.feeds),inputs=list(model.inputs);if(inputs.some((item)=>!names.includes(item.name)))return{score:-100,reasons:['explicit feed names mismatch'],inputPlan:null};
  let score=6;const reasons=['explicit feed names match'];for(const input of inputs){const spec=candidate.feeds[input.name],dims=input.metadata?.dimensions;if(Array.isArray(spec?.dims)&&Array.isArray(dims)){if(fixedMismatch(spec.dims,dims))return{score:-100,reasons:[`feed ${input.name} shape mismatch`],inputPlan:null};score+=2;reasons.push(`feed ${input.name} shape compatible`);}}return{score,reasons,inputPlan:null};
}
function scoreAutomaticInputs(model,context,label){
  const imageDims=context.mode==='image'?expectedImageDims(context.manifest):null;const plan=resolveModelInputPlan(model,{mode:context.mode,npyDims:context.npyDims||null,imageDims,inputBindings:context.inputBindings||null});
  if(!plan.ok)return{score:-100,reasons:[`${plan.code}: ${plan.detail}`],inputPlan:plan};
  let score=2+(plan.auxiliaryInputNames?.length||0)*2;const reasons=[...plan.reasons];if((context.mode==='image'&&imageDims)||(context.mode==='npy'&&context.npyDims)){score+=5;reasons.push(`${label} primary shape compatible`);}if(plan.auxiliaryInputNames?.length)reasons.push(`${plan.auxiliaryInputNames.length} auxiliary input(s) evidence-bound`);
  return{score,reasons,inputPlan:plan};
}
function scoreSingleInput(model,expectedDims,label,allowOptionalBatch=false){
  const inputs=list(model.inputs);if(inputs.length!==1)return{score:-100,reasons:[`${label} requires one input`]};let score=2;const reasons=['single input'];const dims=inputs[0]?.metadata?.dimensions;
  if(expectedDims&&Array.isArray(dims)){const relation=allowOptionalBatch?compatibleWithOptionalBatch(expectedDims,dims):{compatible:compatibleDims(expectedDims,dims),adaptation:'exact'};if(!relation.compatible)return{score:-100,reasons:[`${label} shape mismatch`]};score+=5;reasons.push(`${label} shape compatible${relation.adaptation==='prepend-batch-1'?' via batch=1':''}`);}return{score,reasons};
}
function weakNameScore(file){const name=String(file?.path||'').toLowerCase();let score=0;const reasons=[];if(/classif|model|network|net\b/.test(name)){score+=1;reasons.push('classifier/model filename signal');}if(/backup|old|debug|feature|embed/.test(name)){score-=1;reasons.push('weak auxiliary filename penalty');}return{score,reasons};}
function scoreModel(file,model,context={}){
  let part;if(context.mode==='explicit-feeds')part=scoreExplicit(model,context.explicitBundle);else if(context.mode==='npy')part=scoreAutomaticInputs(model,context,'NPY');else if(context.mode==='image')part=scoreAutomaticInputs(model,context,'image');else part={score:list(model.inputs).length===1?1:0,reasons:[],inputPlan:null};
  if(part.score<=-100)return{file,model,score:part.score,reasons:part.reasons,inputPlan:part.inputPlan||null};const output=vectorOutputScore(model),weak=weakNameScore(file);return{file,model,score:part.score+output+weak.score,reasons:[...part.reasons,...(output?['classification-vector output']:[]),...weak.reasons],inputPlan:part.inputPlan||null};
}

async function inspectCandidate(root,file,inspect){
  if(Number(file.size)>MAX_MODEL_BYTES)throw new Error(`model size ${file.size} exceeds ${MAX_MODEL_BYTES}`);const target=path.resolve(root,String(file.path||''));if(!inside(root,target))throw new Error('model path escapes workspace');
  const stat=await fs.lstat(target);if(!stat.isFile()||stat.isSymbolicLink())throw new Error('model path is not a regular file');const model=await inspect(target,{provider:'cpu'});return{file,target,model};
}
function candidateView(item){return{path:item.file.path,score:item.score,reasons:item.reasons,inputPlan:item.inputPlan?.ok?inputPlanView(item.inputPlan):item.inputPlan?{code:item.inputPlan.code,detail:item.inputPlan.detail,missing:item.inputPlan.missing||null}:null};}

async function selectOnnxModel(rootPath,analysis,context={},options={}){
  const root=path.resolve(String(rootPath||'')),files=modelFiles(analysis);
  if(!files.length)return{ok:false,code:'MODEL_MISSING',detail:'no ONNX model in challenge session',candidates:[]};
  if(files.length>MAX_MODELS)return{ok:false,code:'MODEL_TOO_MANY',detail:`${files.length} ONNX models exceed automatic selection cap ${MAX_MODELS}`,models:files.map((x)=>x.path)};
  const inspect=options.inspectModel||inspectOnnxModel,candidates=[],errors=[];
  for(const file of files){try{const item=await inspectCandidate(root,file,inspect);candidates.push({...item,...scoreModel(file,item.model,context)});}catch(error){errors.push({file:file.path,error:String(error?.message||error).slice(0,300)});}}
  const usable=candidates.filter((item)=>item.score>-100).sort((a,b)=>b.score-a.score||String(a.file.path).localeCompare(String(b.file.path)));
  if(!usable.length)return{ok:false,code:'MODEL_INCOMPATIBLE',detail:'ONNX models exist but none match current candidate/input contract',errors,candidates:candidates.map(candidateView)};
  if(usable.length===1)return{ok:true,...usable[0],selection:{method:'only-compatible',score:usable[0].score,reasons:usable[0].reasons,alternatives:[]},errors};
  const best=usable[0],second=usable[1],margin=best.score-second.score;
  if(margin<2)return{ok:false,code:'MODEL_AMBIGUOUS',detail:`top compatible models are too close (${best.score} vs ${second.score})`,models:usable.map((x)=>x.file.path),candidates:usable.map(candidateView),errors};
  return{ok:true,...best,selection:{method:'compatibility-score',score:best.score,margin,reasons:best.reasons,alternatives:usable.slice(1,5).map(candidateView)},errors};
}

module.exports={MAX_MODELS,expectedImageDims,compatibleWithOptionalBatch,vectorOutputScore,scoreSingleInput,scoreAutomaticInputs,scoreModel,selectOnnxModel};
