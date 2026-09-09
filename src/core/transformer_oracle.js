'use strict';

const { withSession, tensorFromSpec, metadataView, outputView, normalizeProvider } = require('./local_ml_runtime');
const { createGpt2Bpe } = require('./gpt2_bpe');

const MAX_NEW_TOKENS = 256;
const MAX_PROMPT_TOKENS = 65536;
const MAX_VOCAB = 1_000_000;
const MAX_CANDIDATES_PER_STEP = 8192;
const MAX_STEP_PREVIEW = 16;

function records(names, metadata) {
  return (names || []).map((name, index) => ({ name, index, metadata: metadataView(metadata?.[index]) }));
}

function scoreName(name, rules) {
  const value = String(name || '').toLowerCase();
  let best = 0;
  for (const [pattern, score] of rules) if (pattern.test(value)) best = Math.max(best, score);
  return best;
}

function bestRole(items, rules, exclude = () => false) {
  const ranked = items.filter((item) => !exclude(item)).map((item) => ({ item, score:scoreName(item.name, rules) })).filter((item) => item.score > 0).sort((a,b) => b.score - a.score || a.item.index - b.item.index);
  if (!ranked.length) return null;
  if (ranked.length > 1 && ranked[0].score === ranked[1].score) return { ...ranked[0].item, ambiguous:true, alternatives:ranked.filter((item)=>item.score===ranked[0].score).map((item)=>item.item.name) };
  return ranked[0].item;
}

function cacheIdentity(name) {
  const value = String(name || '').toLowerCase();
  const keyed = value.match(/(?:past_key_values|present_key_values|past|present)[._\/-]?(\d+)[._\/-]?(key|value)/i)
    || value.match(/(?:past_key_values|present_key_values|past|present)[._\/-]?(key|value)[._\/-]?(\d+)/i);
  if (keyed) {
    if (/^\d+$/.test(keyed[1])) return { layer:Number(keyed[1]), kind:keyed[2].toLowerCase() };
    return { layer:Number(keyed[2]), kind:keyed[1].toLowerCase() };
  }
  const flat = value.match(/(?:past|present)[._\/-]?(\d+)$/i);
  if (flat) return { slot:Number(flat[1]), kind:'slot' };
  return null;
}

function classifyTransformerSession(session) {
  const inputs = records(session.inputNames, session.inputMetadata);
  const outputs = records(session.outputNames, session.outputMetadata);
  const cacheInputs = inputs.map((item) => ({ item, identity:cacheIdentity(item.name) })).filter((item) => item.identity);
  const cacheOutputs = outputs.map((item) => ({ item, identity:cacheIdentity(item.name) })).filter((item) => item.identity);
  const isCache = (item) => Boolean(cacheIdentity(item.name));

  const inputIds = bestRole(inputs, [
    [/^input_ids$/,100], [/input[_-]?ids$/,95], [/token[_-]?ids$/,90], [/(^|[._/-])ids$/,70]
  ], isCache);
  const attentionMask = bestRole(inputs, [[/^attention_mask$/,100],[/attention.*mask/,90],[/(^|[._/-])mask$/,60]], isCache);
  const positionIds = bestRole(inputs, [[/^position_ids$/,100],[/position.*ids/,90]], isCache);
  const logits = bestRole(outputs, [[/^logits$/,100],[/(^|[._/-])logits$/,95],[/lm.*logits/,90]], isCache);
  const hidden = bestRole(outputs, [[/last_hidden_state/,100],[/hidden_states?[._/-]?\d*$/,90],[/(^|[._/-])hidden$/,70]], isCache);

  const pairs = [];
  for (const input of cacheInputs) {
    const match = cacheOutputs.find((output) => {
      if ('layer' in input.identity && 'layer' in output.identity) return input.identity.layer === output.identity.layer && input.identity.kind === output.identity.kind;
      if ('slot' in input.identity && 'slot' in output.identity) return input.identity.slot === output.identity.slot;
      return false;
    });
    if (match) pairs.push({ input:input.item.name, output:match.item.name, identity:input.identity });
  }
  const cacheMode = !cacheInputs.length && !cacheOutputs.length ? 'none'
    : cacheInputs.length > 0 && pairs.length === cacheInputs.length ? 'paired'
      : 'unpaired';
  const knownInputs = new Set([inputIds?.name, attentionMask?.name, positionIds?.name, ...cacheInputs.map((item)=>item.item.name)].filter(Boolean));
  const unknownInputs = inputs.filter((item)=>!knownInputs.has(item.name));
  const ambiguities = [inputIds,attentionMask,positionIds,logits,hidden].filter((item)=>item?.ambiguous).map((item)=>({ role:item.name===inputIds?.name?'input_ids':item.name===logits?.name?'logits':'aux', alternatives:item.alternatives }));
  return {
    schema:'newcyber.transformer-recipe.v1',
    supported:Boolean(inputIds && logits && !inputIds.ambiguous && !logits.ambiguous),
    roles:{ inputIds, attentionMask, positionIds, logits, hidden },
    cache:{ mode:cacheMode, inputs:cacheInputs.map((item)=>({ name:item.item.name, metadata:item.item.metadata, identity:item.identity })), outputs:cacheOutputs.map((item)=>({ name:item.item.name, metadata:item.item.metadata, identity:item.identity })), pairs },
    unknownInputs:unknownInputs.map((item)=>({ name:item.name, metadata:item.metadata })),
    ambiguities,
    inputs,
    outputs
  };
}

function tensorType(metadata, fallback='int64') {
  const type = String(metadata?.type || '').toLowerCase();
  if (/int64/.test(type)) return 'int64';
  if (/int32/.test(type)) return 'int32';
  if (/float16/.test(type)) return 'float32';
  if (/float/.test(type)) return 'float32';
  if (/bool/.test(type)) return 'bool';
  return fallback;
}

function integerSpec(values, metadata, dims) {
  return { type:tensorType(metadata,'int64'), dims, values };
}

function emptyCacheSpec(item) {
  const dims = Array.isArray(item.metadata?.dimensions) ? item.metadata.dimensions.slice() : [];
  const symbolic = Array.isArray(item.metadata?.symbolicDimensions) ? item.metadata.symbolicDimensions.slice() : [];
  if (!dims.length) return null;
  let zeroEvidence = false;
  const resolved = dims.map((raw, index) => {
    if (Number.isInteger(raw) && raw >= 0) return raw;
    const label = String(symbolic[index] ?? raw ?? '').toLowerCase();
    if (/past|cache|sequence|seq/.test(label)) { zeroEvidence = true; return 0; }
    return 1;
  });
  if (!zeroEvidence) return null;
  const count = resolved.reduce((a,b)=>a*b,1);
  if (count !== 0) return null;
  return { type:tensorType(item.metadata,'float32'), dims:resolved, values:[] };
}

function lastLogitSlice(tensor) {
  if (!tensor?.data || !Array.isArray(tensor.dims) || !tensor.dims.length) throw new Error('logits 输出不是 tensor');
  const vocab = Number(tensor.dims[tensor.dims.length - 1]);
  if (!Number.isSafeInteger(vocab) || vocab <= 0 || vocab > MAX_VOCAB) throw new Error(`logits vocab=${vocab} 非法或超过 ${MAX_VOCAB}`);
  if (tensor.data.length < vocab || tensor.data.length % vocab !== 0) throw new Error('logits data 长度与最后一维不一致');
  const start = tensor.data.length - vocab;
  return { vocab, data:tensor.data, start };
}

function topKLogits(tensor, topK=8, candidateIds=null) {
  const { vocab, data, start } = lastLogitSlice(tensor);
  const k = Math.max(1,Math.min(64,Number(topK)||8));
  let ids;
  if (candidateIds) {
    ids = Array.from(new Set(Array.from(candidateIds, Number))).filter((id)=>Number.isSafeInteger(id)&&id>=0&&id<vocab);
    if (!ids.length) throw new Error('candidate token 集为空或全部越界');
    if (ids.length > MAX_CANDIDATES_PER_STEP) throw new Error(`candidate token 超过 ${MAX_CANDIDATES_PER_STEP} 上限`);
  } else ids = Array.from({length:vocab},(_,id)=>id);
  const ranked = ids.map((id)=>({ id, logit:Number(data[start+id]) })).filter((item)=>Number.isFinite(item.logit)).sort((a,b)=>b.logit-a.logit||a.id-b.id).slice(0,k);
  if (!ranked.length) throw new Error('logits 没有有限候选值');
  return ranked;
}

function lastHiddenVector(tensor) {
  if (!tensor?.data || !Array.isArray(tensor.dims) || !tensor.dims.length) return null;
  const width = Number(tensor.dims[tensor.dims.length-1]);
  if (!Number.isSafeInteger(width) || width <= 0 || width > 32768 || tensor.data.length < width) return null;
  return Array.from(tensor.data.slice(tensor.data.length-width), Number);
}

function findFlag(text) {
  const match = String(text || '').match(/(?:flag|ctf|wqb)\{[^\r\n{}]{1,512}\}/i);
  return match?.[0] || null;
}

function buildTokenizer(spec) {
  if (!spec) return null;
  if (typeof spec.encode === 'function' && typeof spec.decode === 'function') return spec;
  if (typeof spec.vocabText !== 'string') throw new Error('GPT-2 tokenizer 需要 vocabText');
  return createGpt2Bpe(spec.vocabText, spec.mergesText || '');
}

function normalizeTokenIds(values, label='token ids') {
  const ids = Array.from(values || [], Number);
  if (!ids.length) throw new Error(`${label} 不能为空`);
  if (ids.length > MAX_PROMPT_TOKENS) throw new Error(`${label} 超过 ${MAX_PROMPT_TOKENS} 上限`);
  if (ids.some((id)=>!Number.isSafeInteger(id)||id<0)) throw new Error(`${label} 包含非法 id`);
  return ids;
}

function makeFeeds(session, ort, recipe, sequence, stepIds, cacheState, extraFeeds, pastLength) {
  const feeds = {};
  const roles = recipe.roles;
  const idsForModel = recipe.cache.mode === 'paired' && cacheState ? stepIds : sequence;
  feeds[roles.inputIds.name] = tensorFromSpec(ort, integerSpec(idsForModel, roles.inputIds.metadata, [1,idsForModel.length]));
  if (roles.attentionMask) {
    const total = pastLength + idsForModel.length;
    feeds[roles.attentionMask.name] = tensorFromSpec(ort, integerSpec(Array(total).fill(1), roles.attentionMask.metadata, [1,total]));
  }
  if (roles.positionIds) {
    const start = pastLength;
    feeds[roles.positionIds.name] = tensorFromSpec(ort, integerSpec(Array.from({length:idsForModel.length},(_,i)=>start+i), roles.positionIds.metadata, [1,idsForModel.length]));
  }
  for (const item of recipe.cache.inputs) {
    if (cacheState?.[item.name]) feeds[item.name] = cacheState[item.name];
    else {
      const empty = emptyCacheSpec(item);
      if (!empty) throw new Error(`cache-init-gap:${item.name} 缺少可证明的 zero-length sequence 维`);
      feeds[item.name] = tensorFromSpec(ort, empty);
    }
  }
  const extras = extraFeeds || {};
  for (const item of recipe.unknownInputs) {
    const spec = extras[item.name];
    if (!spec) throw new Error(`unknown-input-gap:${item.name}`);
    feeds[item.name] = tensorFromSpec(ort, spec);
  }
  for (const name of session.inputNames) if (!feeds[name]) throw new Error(`未构建 ONNX 输入 ${name}`);
  return feeds;
}

async function runTransformerDecode(model, request={}, options={}) {
  const maxNewTokens = Math.max(1,Math.min(MAX_NEW_TOKENS,Number(request.maxNewTokens)||32));
  const topK = Math.max(1,Math.min(64,Number(request.topK)||8));
  const tokenizer = buildTokenizer(request.tokenizer || null);
  let promptIds;
  if (Array.isArray(request.promptTokenIds) || ArrayBuffer.isView(request.promptTokenIds)) promptIds = normalizeTokenIds(request.promptTokenIds,'promptTokenIds');
  else if (typeof request.promptText === 'string' && tokenizer) promptIds = normalizeTokenIds(tokenizer.encode(request.promptText),'encoded prompt');
  else throw new Error('需要 promptTokenIds，或 promptText + GPT-2 tokenizer');
  const stopIds = new Set(Array.from(request.stopTokenIds || [],Number).filter((id)=>Number.isSafeInteger(id)&&id>=0));
  const candidateByStep = Array.isArray(request.candidateTokenIdsByStep) ? request.candidateTokenIdsByStep : [];

  return withSession(model, options, async (session, ort) => {
    const recipe = classifyTransformerSession(session);
    if (!recipe.supported) return { schema:'newcyber.transformer-decode.v1', status:'recipe-gap', provider:normalizeProvider(options.provider||'cpu'), recipe, notes:['无法唯一识别 token ids / logits；不会按固定 GPT-2 名称强绑。'] };
    if (recipe.cache.mode === 'unpaired') return { schema:'newcyber.transformer-decode.v1', status:'cache-pair-gap', provider:normalizeProvider(options.provider||'cpu'), recipe, notes:['模型暴露 cache I/O，但无法可靠配对 past↔present；停止增量执行，避免错绑层。'] };

    const sequence = promptIds.slice();
    const generated = [];
    const steps = [];
    let cacheState = null;
    let pastLength = 0;
    let status = 'max-tokens';
    let flag = null;
    for (let step=0; step<maxNewTokens; step+=1) {
      const stepIds = step === 0 ? sequence.slice() : [sequence[sequence.length-1]];
      let feeds;
      try { feeds = makeFeeds(session,ort,recipe,sequence,stepIds,cacheState,request.extraFeeds,pastLength); }
      catch (error) { return { schema:'newcyber.transformer-decode.v1', status:String(error?.message||error).split(':')[0], provider:normalizeProvider(options.provider||'cpu'), recipe, generatedTokenIds:generated, steps, gap:error?.message||String(error) }; }
      const wanted = new Set([recipe.roles.logits.name]);
      if (request.captureHidden && recipe.roles.hidden) wanted.add(recipe.roles.hidden.name);
      for (const pair of recipe.cache.pairs) wanted.add(pair.output);
      const output = await session.run(feeds,Object.fromEntries(Array.from(wanted,(name)=>[name,null])));
      const candidates = candidateByStep[step] ? normalizeTokenIds(candidateByStep[step],`candidate step ${step}`) : null;
      const ranked = topKLogits(output[recipe.roles.logits.name],topK,candidates);
      const chosen = ranked[0].id;
      generated.push(chosen);
      sequence.push(chosen);
      const hidden = request.captureHidden && recipe.roles.hidden ? lastHiddenVector(output[recipe.roles.hidden.name]) : null;
      steps.push({ index:step, tokenId:chosen, top:ranked.slice(0,MAX_STEP_PREVIEW), hidden: hidden ? { width:hidden.length, preview:hidden.slice(0,128), truncated:hidden.length>128 } : null });

      if (recipe.cache.mode === 'paired') {
        const next = {};
        for (const pair of recipe.cache.pairs) {
          const tensor = output[pair.output];
          if (!tensor) return { schema:'newcyber.transformer-decode.v1', status:'cache-output-gap', provider:normalizeProvider(options.provider||'cpu'), recipe, generatedTokenIds:generated, steps, gap:`缺少 cache output ${pair.output}` };
          next[pair.input] = tensor;
        }
        cacheState = next;
        pastLength = sequence.length;
      } else {
        cacheState = null;
        pastLength = 0;
      }

      let decoded = null;
      if (tokenizer) {
        try { decoded = tokenizer.decode(sequence); } catch {}
        flag = decoded ? findFlag(decoded) : null;
      }
      if (flag) { status='flag-recovered'; break; }
      if (stopIds.has(chosen)) { status='stop-token'; break; }
    }
    let text = null;
    let generatedText = null;
    if (tokenizer) {
      try { text = tokenizer.decode(sequence); } catch {}
      try { generatedText = tokenizer.decode(generated); } catch {}
    }
    return {
      schema:'newcyber.transformer-decode.v1',
      status,
      provider:normalizeProvider(options.provider||'cpu'),
      recipe,
      promptTokenIds:promptIds,
      generatedTokenIds:generated,
      text,
      generatedText,
      flag,
      cacheUsed:recipe.cache.mode==='paired',
      steps
    };
  });
}

function inspectTransformerModel(model, options={}) {
  return withSession(model,options,async (session)=>classifyTransformerSession(session));
}

module.exports = {
  MAX_NEW_TOKENS,
  cacheIdentity,
  classifyTransformerSession,
  topKLogits,
  findFlag,
  inspectTransformerModel,
  runTransformerDecode,
  outputView
};
