'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('fs');
const path=require('path');
const {bytesToUnicodeMaps,createGpt2Bpe}=require('../src/core/gpt2_bpe');
const {classifyTransformerSession,runTransformerDecode}=require('../src/core/transformer_oracle');
const {fitLeakageProfile,recoverHiddenState,rankProbeCandidates,recoverProbeCandidates}=require('../src/core/side_channel_probe');

function byteTokenizerSpec(){
  const maps=bytesToUnicodeMaps();
  const vocab={};
  for(const [byte,ch] of maps.encoder.entries())vocab[ch]=byte;
  return {vocabText:JSON.stringify(vocab),mergesText:'#version: 0.2\n'};
}

test('Batch34 GPT2 byte-level tokenizer round-trips UTF-8 without a challenge-specific vocab',()=>{
  const spec=byteTokenizerSpec();
  const tok=createGpt2Bpe(spec.vocabText,spec.mergesText);
  const text='Hi, 世界! flag{x}';
  const ids=tok.encode(text);
  assert.ok(ids.length>text.length);
  assert.equal(tok.decode(ids),text);
});

function fakeNoCacheOrt(targetText){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  const target=Buffer.from(targetText,'utf8');
  const session={
    inputNames:['token_ids'],outputNames:['lm_logits'],
    inputMetadata:[{type:'tensor(int64)',dimensions:[1,'sequence']}],
    outputMetadata:[{type:'tensor(float)',dimensions:[1,'sequence',256]}],
    async run(feeds){
      const seq=feeds.token_ids.data.length;
      const next=target[Math.max(0,seq-1)]??125;
      const data=new Float32Array(seq*256).fill(-10);
      data[(seq-1)*256+next]=10;
      return {lm_logits:new Tensor('float32',data,[1,seq,256])};
    },async release(){}
  };
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

test('Batch34 metadata-driven transformer decode recovers a flag without fixed GPT2 input/output names',async()=>{
  const ort=fakeNoCacheOrt('flag{variant_names}');
  const result=await runTransformerDecode(new Uint8Array([1]),{
    promptTokenIds:[65],tokenizer:byteTokenizerSpec(),maxNewTokens:32,topK:4
  },{ort,provider:'cpu'});
  assert.equal(result.recipe.roles.inputIds.name,'token_ids');
  assert.equal(result.recipe.roles.logits.name,'lm_logits');
  assert.equal(result.cacheUsed,false);
  assert.equal(result.status,'flag-recovered');
  assert.equal(result.flag,'flag{variant_names}');
});

function fakeCacheOrt(targetText){
  class Tensor{constructor(type,data,dims){this.type=type;this.data=data;this.dims=dims;}}
  const target=Buffer.from(targetText,'utf8');
  let call=0;
  const session={
    inputNames:['input_ids','attention_mask','past_key_values.0.key','past_key_values.0.value'],
    outputNames:['logits','present.0.key','present.0.value'],
    inputMetadata:[
      {type:'tensor(int64)',dimensions:[1,'sequence']},
      {type:'tensor(int64)',dimensions:[1,'total_sequence']},
      {type:'tensor(float)',dimensions:[1,1,'past_sequence_length',2],symbolicDimensions:[null,null,'past_sequence_length',null]},
      {type:'tensor(float)',dimensions:[1,1,'past_sequence_length',2],symbolicDimensions:[null,null,'past_sequence_length',null]}
    ],
    outputMetadata:[
      {type:'tensor(float)',dimensions:[1,'sequence',256]},
      {type:'tensor(float)',dimensions:[1,1,'total_sequence',2]},
      {type:'tensor(float)',dimensions:[1,1,'total_sequence',2]}
    ],
    async run(feeds){
      const ids=feeds.input_ids.data.length;
      const next=target[call++]??125;
      const logits=new Float32Array(ids*256).fill(-9);
      logits[(ids-1)*256+next]=9;
      const past=Number(feeds['past_key_values.0.key'].dims[2]||0);
      const total=past+ids;
      return {
        logits:new Tensor('float32',logits,[1,ids,256]),
        'present.0.key':new Tensor('float32',new Float32Array(total*2),[1,1,total,2]),
        'present.0.value':new Tensor('float32',new Float32Array(total*2),[1,1,total,2])
      };
    },async release(){}
  };
  return {Tensor,InferenceSession:{async create(){return session;}}};
}

test('Batch34 pairs KV cache structurally and reuses it for incremental decoding',async()=>{
  const ort=fakeCacheOrt('ctf{cache_ok}');
  const result=await runTransformerDecode(new Uint8Array([1]),{
    promptTokenIds:[66],tokenizer:byteTokenizerSpec(),maxNewTokens:24
  },{ort,provider:'cpu'});
  assert.equal(result.recipe.cache.mode,'paired');
  assert.equal(result.recipe.cache.pairs.length,2);
  assert.equal(result.cacheUsed,true);
  assert.equal(result.flag,'ctf{cache_ok}');
});

test('Batch34 refuses ambiguous or unpaired transformer cache instead of positional guessing',()=>{
  const session={
    inputNames:['input_ids','past_key_values.0.key','past_key_values.0.value'],
    outputNames:['logits','present.1.key','present.1.value'],
    inputMetadata:[{},{},{}],outputMetadata:[{},{},{}]
  };
  const recipe=classifyTransformerSession(session);
  assert.equal(recipe.supported,true);
  assert.equal(recipe.cache.mode,'unpaired');
  assert.equal(recipe.cache.pairs.length,0);
});

test('Batch34 fits a generic low-dimensional leakage profile and recovers hidden state',()=>{
  const hidden=[];const leakage=[];
  for(let i=0;i<60;i+=1){
    const h=[(i%7)-3,((i*3)%11)-5,((i*5)%13)-6];
    hidden.push(h);
    leakage.push([
      2+1.5*h[0]-2*h[1]+.25*h[2],
      -1+.5*h[0]+.75*h[1]-1.25*h[2],
      4-h[0]+2*h[2],
      .3+2*h[1]-.5*h[2]
    ]);
  }
  const profile=fitLeakageProfile(hidden,leakage,{lambda:1e-10});
  assert.equal(profile.status,'ok');
  assert.equal(profile.hiddenDim,3);
  assert.equal(profile.leakageDim,4);
  assert.ok(profile.r2>.999999999);
  const target=[1.25,-2.5,.75];
  const y=[2+1.5*target[0]-2*target[1]+.25*target[2],-1+.5*target[0]+.75*target[1]-1.25*target[2],4-target[0]+2*target[2],.3+2*target[1]-.5*target[2]];
  const recovered=recoverHiddenState(profile,y);
  assert.equal(recovered.status,'ok');
  recovered.hidden.forEach((value,index)=>assert.ok(Math.abs(value-target[index])<1e-6));
});

test('Batch34 probe ranking is explicit about orientation and maps recovered hidden to arbitrary token ids',()=>{
  const hidden=[1.2,-.7,.3];
  const square=[[1,0,0],[0,1,0],[0,0,1]];
  assert.equal(rankProbeCandidates(hidden,square).status,'orientation-gap');
  const probe=[[9,9,9],[1.2,-.7,.3],[-1,2,4],[.5,.5,.5]];
  const rank=rankProbeCandidates(hidden,probe,{orientation:'candidate-rows',metric:'negative-l2',candidateIds:[7,4242,99,123],topK:3});
  assert.equal(rank.status,'ok');
  assert.equal(rank.top[0].tokenId,4242);
});

test('Batch34 full leakage→hidden→probe chain stays generic and preserves ranked candidates',()=>{
  const hidden=[];const leakage=[];
  for(let i=0;i<40;i+=1){const h=[i%5,(i%7)-3];hidden.push(h);leakage.push([1+2*h[0]-h[1],-2+.5*h[0]+3*h[1],4-h[0]+.25*h[1]]);}
  const profile=fitLeakageProfile(hidden,leakage,{lambda:1e-9});
  const target=[2,-1];
  const y=[1+2*target[0]-target[1],-2+.5*target[0]+3*target[1],4-target[0]+.25*target[1]];
  const chain=recoverProbeCandidates(profile,y,[[2,-1],[0,0],[3,3]],{probe:{orientation:'candidate-rows',metric:'negative-l2',candidateIds:[501,502,503]}});
  assert.equal(chain.status,'ok');
  assert.equal(chain.ranking.top[0].tokenId,501);
});

test('Batch34 source and UI wiring is dedicated to transformer/SCA evidence, not a generic textbox',()=>{
  const core=fs.readFileSync(path.join(__dirname,'..','src','core','transformer_oracle.js'),'utf8');
  const probe=fs.readFileSync(path.join(__dirname,'..','src','core','side_channel_probe.js'),'utf8');
  assert.match(core,/cache-pair-gap/);
  assert.match(core,/candidateTokenIdsByStep/);
  assert.match(probe,/orientation-gap/);
});
