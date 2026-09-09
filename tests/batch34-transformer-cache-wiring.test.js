'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {runTransformerDecode}=require('../src/core/transformer_oracle');

function strictCacheOrt(){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  let call=0;
  const session={
    inputNames:['input_ids','attention_mask','position_ids','past_key_values.0.key','past_key_values.0.value'],
    outputNames:['logits','present.0.key','present.0.value'],
    inputMetadata:[
      {type:'tensor(int64)',dimensions:[1,'sequence']},
      {type:'tensor(int64)',dimensions:[1,'total_sequence']},
      {type:'tensor(int64)',dimensions:[1,'sequence']},
      {type:'tensor(float)',dimensions:[1,1,'past_sequence_length',2],symbolicDimensions:[null,null,'past_sequence_length',null]},
      {type:'tensor(float)',dimensions:[1,1,'past_sequence_length',2],symbolicDimensions:[null,null,'past_sequence_length',null]}
    ],
    outputMetadata:[{type:'tensor(float)',dimensions:[1,'sequence',10]},{type:'tensor(float)'},{type:'tensor(float)'}],
    async run(feeds){
      if(call===0){
        assert.deepEqual(feeds.input_ids.dims,[1,2]);
        assert.deepEqual(feeds.attention_mask.dims,[1,2]);
        assert.deepEqual(Array.from(feeds.position_ids.data,Number),[0,1]);
        assert.equal(feeds['past_key_values.0.key'].dims[2],0);
      }else if(call===1){
        assert.deepEqual(feeds.input_ids.dims,[1,1]);
        assert.deepEqual(feeds.attention_mask.dims,[1,3]);
        assert.deepEqual(Array.from(feeds.position_ids.data,Number),[2]);
        assert.equal(feeds['past_key_values.0.key'].dims[2],2);
      }
      const ids=feeds.input_ids.data.length;
      const logits=new Float32Array(ids*10).fill(-1);
      logits[(ids-1)*10+1]=5;
      const past=Number(feeds['past_key_values.0.key'].dims[2]||0);
      const total=past+ids;
      call+=1;
      return {logits:new Tensor('float32',logits,[1,ids,10]),'present.0.key':new Tensor('float32',new Float32Array(total*2),[1,1,total,2]),'present.0.value':new Tensor('float32',new Float32Array(total*2),[1,1,total,2])};
    },async release(){}
  };
  return {ort:{Tensor,InferenceSession:{async create(){return session;}}},calls:()=>call};
}

test('Batch34 KV incremental timeline keeps past length separate from newly selected token',async()=>{
  const fake=strictCacheOrt();
  const result=await runTransformerDecode(new Uint8Array([1]),{promptTokenIds:[3,4],maxNewTokens:2},{ort:fake.ort,provider:'cpu'});
  assert.equal(result.cacheUsed,true);
  assert.equal(fake.calls(),2);
});

test('Batch34 dedicated transformer UI and isolated preload expose bounded oracle/probe actions',()=>{
  const renderer=fs.readFileSync(path.join(__dirname,'..','renderer','ai_transformer_oracle_tools.js'),'utf8');
  const css=fs.readFileSync(path.join(__dirname,'..','renderer','styles','ai_transformer_oracle.css'),'utf8');
  const html=fs.readFileSync(path.join(__dirname,'..','renderer','toolbox.html'),'utf8');
  const preload=fs.readFileSync(path.join(__dirname,'..','preload.js'),'utf8');
  const ipc=fs.readFileSync(path.join(__dirname,'..','src','electron','ai_sca_ipc.js'),'utf8');
  assert.doesNotThrow(()=>new Function(renderer));
  assert.match(renderer,/MODEL \/ IO RECIPE/);
  assert.match(renderer,/SCA CANDIDATE CONSTRAINT/);
  assert.match(renderer,/KV INCREMENTAL/);
  assert.match(css,/\.tx-workbench/);
  assert.match(html,/ai_transformer_oracle\.css/);
  assert.match(html,/ai_transformer_oracle_tools\.js/);
  assert.match(preload,/runTransformerOracle/);
  assert.match(preload,/fitScaLeakageProfile/);
  assert.match(preload,/recoverScaProbeCandidates/);
  assert.match(ipc,/ai:transformer-run/);
  assert.match(ipc,/tokenizerSibling/);
  assert.doesNotMatch(renderer,/onnxruntime-node/);
});
