const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeOcrExtractionTranscript }=require('../src/core/ai_ocr_extraction');
const { runTool }=require('../src/core/tool_router');

test('OCR extraction audit detects char confidence, layout and deterministic repeat exposure',()=>{
  const rows=[];
  for(let i=0;i<6;i+=1) rows.push({
    image_id:`img-${i%3}`,
    text:i%2?'HELLO':'WORLD',
    char_confidences:i%2?[0.991234,0.982345,0.973456,0.994567,0.965678]:[0.981111,0.972222,0.963333,0.954444,0.945555],
    boxes:[[10.12345,20.12345,80.12345,24.12345]]
  });
  const result=analyzeOcrExtractionTranscript(rows);
  assert.equal(result.rows,6);
  assert.equal(result.uniqueQueries,3);
  assert.equal(result.duplicateQueries,3);
  assert.ok(result.charConfidenceRows>=6);
  assert.ok(result.boxRows>=6);
  assert.ok(result.findings.some((x)=>x.id==='ocr-char-confidence-exposure'));
});

test('tool router exposes OCR extraction audit',()=>{
  const result=runTool('ai-ocr-extraction',{input:JSON.stringify([{image_id:'a',text:'ABC',char_confidences:[0.9,0.8,0.9]}])});
  assert.equal(result.rows,1);
  assert.equal(result.charsetSize,3);
});
