const os = require('os');
const { parseNpyAdvanced } = require('./model_artifacts');

const MAX_RASTER_PIXELS = 512 * 512;
const MAX_NUMERIC_SCAN = 250000;
const CTF_FREQUENCY_REFERENCE = Object.freeze({
  source: '第五届湾区杯 CTF Final · 耄耋 public writeup',
  outerRadiusRatio: 0.85,
  delta: 0.125,
  note: '0.125 仅是该公开题解使用的赛题阈值，不是通用 AIGC / Deepfake 判定标准。'
});

function round(value, digits = 6) {
  return Number.isFinite(value) ? Number(value.toFixed(digits)) : null;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function std(values, average = mean(values)) {
  if (!values.length) return 0;
  return Math.sqrt(values.reduce((sum, value) => sum + ((value - average) ** 2), 0) / values.length);
}

function quantile(sorted, q) {
  if (!sorted.length) return null;
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  if (lo === hi) return sorted[lo];
  const weight = pos - lo;
  return sorted[lo] * (1 - weight) + sorted[hi] * weight;
}

function normalizeRasterInput(input) {
  const width = Number(input?.width);
  const height = Number(input?.height);
  const channels = Number(input?.channels || 4);
  if (!Number.isInteger(width) || !Number.isInteger(height) || width <= 0 || height <= 0) throw new Error('图像 width / height 无效');
  if (width * height > MAX_RASTER_PIXELS) throw new Error(`图像分析像素超过上限 ${MAX_RASTER_PIXELS}`);
  if (![1, 3, 4].includes(channels)) throw new Error('channels 仅支持 1 / 3 / 4');
  const expected = width * height * channels;
  let data = input?.data;
  if (typeof data === 'string') data = [...Buffer.from(data, 'base64')];
  if (!Array.isArray(data) && !ArrayBuffer.isView(data)) throw new Error('图像 data 需要数组 / TypedArray / base64');
  if (data.length < expected) throw new Error(`图像数据不足：需要 ${expected}，实际 ${data.length}`);
  const pixels = new Uint8Array(expected);
  for (let i = 0; i < expected; i += 1) pixels[i] = clamp(Math.round(Number(data[i]) || 0), 0, 255);
  return { width, height, channels, data: pixels };
}

function rgbAt(raster, x, y) {
  const index = (y * raster.width + x) * raster.channels;
  if (raster.channels === 1) {
    const value = raster.data[index];
    return [value, value, value];
  }
  return [raster.data[index], raster.data[index + 1], raster.data[index + 2]];
}

function luminance(rgb) {
  return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
}

function rasterStats(raster) {
  const channelValues = [[], [], []];
  const lumas = new Float64Array(raster.width * raster.height);
  let clipped = 0;
  let edgeSum = 0;
  let edgeCount = 0;
  for (let y = 0; y < raster.height; y += 1) {
    for (let x = 0; x < raster.width; x += 1) {
      const rgb = rgbAt(raster, x, y);
      for (let c = 0; c < 3; c += 1) channelValues[c].push(rgb[c]);
      if (rgb.some((value) => value <= 1 || value >= 254)) clipped += 1;
      const lum = luminance(rgb);
      lumas[y * raster.width + x] = lum;
      if (x > 0) { edgeSum += Math.abs(lum - lumas[y * raster.width + x - 1]); edgeCount += 1; }
      if (y > 0) { edgeSum += Math.abs(lum - lumas[(y - 1) * raster.width + x]); edgeCount += 1; }
    }
  }
  const channels = channelValues.map((values, index) => {
    const avg = mean(values);
    const deviation = std(values, avg);
    return { channel: ['R', 'G', 'B'][index], min: Math.min(...values), max: Math.max(...values), mean: round(avg), std: round(deviation) };
  });
  const histogram = Array(32).fill(0);
  for (const value of lumas) histogram[Math.min(31, Math.floor(value / 8))] += 1;
  let entropy = 0;
  const total = lumas.length;
  for (const count of histogram) {
    if (!count) continue;
    const p = count / total;
    entropy -= p * Math.log2(p);
  }
  const lumaArray = Array.from(lumas);
  const lumaMean = mean(lumaArray);
  return {
    channels,
    luma: { mean: round(lumaMean), std: round(std(lumaArray, lumaMean)), entropyBits32Bins: round(entropy) },
    clippedPixelRatio: round(clipped / Math.max(total, 1)),
    meanEdgeDelta: round(edgeCount ? edgeSum / edgeCount : 0),
    histogram
  };
}

function blockPatchCandidates(raster, stats) {
  const width = raster.width;
  const height = raster.height;
  const block = Math.max(2, Math.min(16, Math.floor(Math.min(width, height) / 8) || 2));
  const stride = Math.max(1, Math.floor(block / 2));
  const globalStd = Math.max(stats.luma.std || 0, 4);
  const candidates = [];
  const grid = [];
  for (let y = 0; y < height; y += stride) {
    for (let x = 0; x < width; x += stride) {
      const x2 = Math.min(width, x + block);
      const y2 = Math.min(height, y + block);
      if (x2 - x < 2 || y2 - y < 2) continue;
      const inside = [];
      let saturated = 0;
      for (let yy = y; yy < y2; yy += 1) {
        for (let xx = x; xx < x2; xx += 1) {
          const rgb = rgbAt(raster, xx, yy);
          const lum = luminance(rgb);
          inside.push(lum);
          if (rgb.some((value) => value <= 3 || value >= 252)) saturated += 1;
        }
      }
      const insideMean = mean(inside);
      const insideStd = std(inside, insideMean);
      const ring = [];
      for (let yy = Math.max(0, y - 1); yy <= Math.min(height - 1, y2); yy += 1) {
        for (let xx = Math.max(0, x - 1); xx <= Math.min(width - 1, x2); xx += 1) {
          if (xx >= x && xx < x2 && yy >= y && yy < y2) continue;
          ring.push(luminance(rgbAt(raster, xx, yy)));
        }
      }
      const ringMean = ring.length ? mean(ring) : stats.luma.mean;
      const contrastZ = Math.abs(insideMean - ringMean) / globalStd;
      const flatness = clamp(1 - (insideStd / globalStd), 0, 1);
      const saturationRatio = saturated / Math.max(inside.length, 1);
      const score = contrastZ * 0.58 + flatness * 0.24 + saturationRatio * 0.18;
      const item = { x, y, width: x2 - x, height: y2 - y, score: round(score), contrastZ: round(contrastZ), flatness: round(flatness), saturationRatio: round(saturationRatio) };
      grid.push(item);
      if (score >= 0.9) candidates.push(item);
    }
  }
  candidates.sort((a, b) => b.score - a.score || a.y - b.y || a.x - b.x);
  return { blockSize: block, stride, candidates: candidates.slice(0, 12), grid: grid.slice(0, 600) };
}

function downsampleGray(raster, maxSide = 32) {
  const width = Math.min(maxSide, raster.width);
  const height = Math.min(maxSide, raster.height);
  const values = new Float64Array(width * height);
  for (let y = 0; y < height; y += 1) {
    const sy = Math.min(raster.height - 1, Math.floor((y + 0.5) * raster.height / height));
    for (let x = 0; x < width; x += 1) {
      const sx = Math.min(raster.width - 1, Math.floor((x + 0.5) * raster.width / width));
      values[y * width + x] = (luminance(rgbAt(raster, sx, sy)) / 255) * 2 - 1;
    }
  }
  return { width, height, values };
}

function frequencyProfile(raster, outerRadiusRatio = CTF_FREQUENCY_REFERENCE.outerRadiusRatio) {
  const small = downsampleGray(raster, 32);
  const { width, height, values } = small;
  const rowReal = Array.from({ length: height }, () => new Float64Array(width));
  const rowImag = Array.from({ length: height }, () => new Float64Array(width));
  for (let y = 0; y < height; y += 1) {
    for (let u = 0; u < width; u += 1) {
      let real = 0;
      let imag = 0;
      for (let x = 0; x < width; x += 1) {
        const angle = -2 * Math.PI * u * x / width;
        const value = values[y * width + x];
        real += value * Math.cos(angle);
        imag += value * Math.sin(angle);
      }
      rowReal[y][u] = real;
      rowImag[y][u] = imag;
    }
  }
  let total = 0;
  let high = 0;
  const radius = Math.min(width, height) * 0.5 * outerRadiusRatio;
  for (let v = 0; v < height; v += 1) {
    const fy = v <= height / 2 ? v : v - height;
    for (let u = 0; u < width; u += 1) {
      const fx = u <= width / 2 ? u : u - width;
      let real = 0;
      let imag = 0;
      for (let y = 0; y < height; y += 1) {
        const angle = -2 * Math.PI * v * y / height;
        const c = Math.cos(angle);
        const s = Math.sin(angle);
        real += rowReal[y][u] * c - rowImag[y][u] * s;
        imag += rowReal[y][u] * s + rowImag[y][u] * c;
      }
      const magnitude = Math.hypot(real, imag);
      total += magnitude;
      if (Math.hypot(fx, fy) >= radius) high += magnitude;
    }
  }
  const ratio = total ? high / total : 0;
  return {
    method: '2D-DFT magnitude ratio on grayscale [-1,1] downsample',
    sampledWidth: width,
    sampledHeight: height,
    outerRadiusRatio,
    highFrequencyRatio: round(ratio),
    ctfReference: { ...CTF_FREQUENCY_REFERENCE, relation: ratio > CTF_FREQUENCY_REFERENCE.delta ? 'above-public-writeup-delta' : 'below-public-writeup-delta' }
  };
}

function analyzeRasterImage(input) {
  const raster = normalizeRasterInput(input);
  const stats = rasterStats(raster);
  const patches = blockPatchCandidates(raster, stats);
  const frequency = frequencyProfile(raster);
  const findings = [];
  if (patches.candidates[0]?.score >= 1.4) findings.push({
    id: 'localized-patch-anomaly-candidate',
    severity: 'medium',
    title: '存在局部 Patch / Trigger 候选热区',
    evidence: patches.candidates.slice(0, 4),
    meaning: '局部区域与邻域存在较强亮度/平坦度/饱和差异。它可作为后门 trigger 排查起点，但不能单凭像素统计确认后门。'
  });
  findings.push({
    id: 'frequency-domain-profile',
    severity: 'info',
    title: '已生成图像频域高频占比',
    evidence: { highFrequencyRatio: frequency.highFrequencyRatio, outerRadiusRatio: frequency.outerRadiusRatio },
    meaning: CTF_FREQUENCY_REFERENCE.note
  });
  return {
    schema: 'newcyber.ai-raster-forensics.v1',
    width: raster.width,
    height: raster.height,
    channels: raster.channels,
    stats,
    patchAnalysis: patches,
    frequency,
    findings,
    notes: [
      'Patch 热区是确定性像素统计候选，不等于已证明存在模型后门。',
      CTF_FREQUENCY_REFERENCE.note,
      '频域指标用于比赛取证/分组辅助；真实 AIGC 检测应在同一数据集上校准阈值并保留验证集。'
    ]
  };
}

function compareRasterImages(input) {
  const left = normalizeRasterInput(input?.left);
  const right = normalizeRasterInput(input?.right);
  if (left.width !== right.width || left.height !== right.height) throw new Error('对照图像尺寸必须一致');
  const pixelCount = left.width * left.height;
  let l0 = 0;
  let l1 = 0;
  let l2sq = 0;
  let linf = 0;
  let changedPixels = 0;
  let minX = left.width;
  let minY = left.height;
  let maxX = -1;
  let maxY = -1;
  const cellW = Math.max(1, Math.ceil(left.width / 8));
  const cellH = Math.max(1, Math.ceil(left.height / 8));
  const heat = Array.from({ length: 8 }, () => Array(8).fill(0));
  const heatCount = Array.from({ length: 8 }, () => Array(8).fill(0));
  for (let y = 0; y < left.height; y += 1) {
    for (let x = 0; x < left.width; x += 1) {
      const a = rgbAt(left, x, y);
      const b = rgbAt(right, x, y);
      let pixelMax = 0;
      let pixelMean = 0;
      for (let c = 0; c < 3; c += 1) {
        const delta = Math.abs(a[c] - b[c]) / 255;
        if (delta > 1 / 255) l0 += 1;
        l1 += delta;
        l2sq += delta ** 2;
        linf = Math.max(linf, delta);
        pixelMax = Math.max(pixelMax, delta);
        pixelMean += delta / 3;
      }
      if (pixelMax > 2 / 255) {
        changedPixels += 1;
        minX = Math.min(minX, x); minY = Math.min(minY, y); maxX = Math.max(maxX, x); maxY = Math.max(maxY, y);
      }
      const gx = Math.min(7, Math.floor(x / cellW));
      const gy = Math.min(7, Math.floor(y / cellH));
      heat[gy][gx] += pixelMean;
      heatCount[gy][gx] += 1;
    }
  }
  for (let gy = 0; gy < 8; gy += 1) for (let gx = 0; gx < 8; gx += 1) heat[gy][gx] = round(heatCount[gy][gx] ? heat[gy][gx] / heatCount[gy][gx] : 0);
  const box = maxX >= minX ? { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 } : null;
  const boxAreaRatio = box ? (box.width * box.height) / pixelCount : 0;
  const changedRatio = changedPixels / pixelCount;
  const localized = Boolean(box && boxAreaRatio <= 0.25 && changedRatio <= 0.2 && linf >= 0.03);
  const findings = localized ? [{
    id: 'localized-adversarial-diff-candidate', severity: 'medium', title: '差异集中在局部区域',
    evidence: { changedRatio: round(changedRatio), box, boxAreaRatio: round(boxAreaRatio), linf: round(linf) },
    meaning: '差分呈局部集中，可优先检查 patch trigger、贴片后门或局部对抗扰动；仍需结合模型输出和攻击约束验证。'
  }] : [];
  return {
    schema: 'newcyber.ai-raster-compare.v1',
    width: left.width,
    height: left.height,
    norms: { l0, l1: round(l1), l2: round(Math.sqrt(l2sq)), linf: round(linf), meanAbs: round(l1 / Math.max(pixelCount * 3, 1)) },
    changedPixels,
    changedRatio: round(changedRatio),
    diffBoundingBox: box,
    boundingBoxAreaRatio: round(boxAreaRatio),
    localizedChangeCandidate: localized,
    heatmap8x8: heat,
    findings,
    notes: ['差分范数按 RGB / 255 归一化；这用于样本约束和热区定位，不代表模型一定被攻击成功。']
  };
}

function parseDescriptor(descr) {
  const match = String(descr || '').match(/^([<>=|])([?bBiuf])([0-9]+)$/);
  if (!match) return null;
  return { endian: match[1], kind: match[2], bytes: Number(match[3]) };
}

function halfToFloat(value) {
  const sign = (value & 0x8000) ? -1 : 1;
  const exponent = (value >> 10) & 0x1f;
  const fraction = value & 0x3ff;
  if (exponent === 0) return sign * Math.pow(2, -14) * (fraction / 1024);
  if (exponent === 31) return fraction ? NaN : sign * Infinity;
  return sign * Math.pow(2, exponent - 15) * (1 + fraction / 1024);
}

function makeNumericReader(buffer, parsed) {
  const descriptor = parseDescriptor(parsed.descr);
  if (!descriptor || parsed.objectDtype || !parsed.itemBytes) return null;
  const little = descriptor.endian === '<' || descriptor.endian === '|' || (descriptor.endian === '=' && os.endianness() === 'LE');
  const start = parsed.payloadOffset;
  const bytes = descriptor.bytes;
  const read = (index) => {
    const offset = start + index * bytes;
    if (offset + bytes > buffer.length) return null;
    try {
      if (descriptor.kind === '?') return buffer[offset] ? 1 : 0;
      if (descriptor.kind === 'u' || descriptor.kind === 'B') {
        if (bytes === 1) return buffer[offset];
        if (bytes === 2) return little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
        if (bytes === 4) return little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
        if (bytes === 8) return Number(little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset));
      }
      if (descriptor.kind === 'i' || descriptor.kind === 'b') {
        if (bytes === 1) return buffer.readInt8(offset);
        if (bytes === 2) return little ? buffer.readInt16LE(offset) : buffer.readInt16BE(offset);
        if (bytes === 4) return little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
        if (bytes === 8) return Number(little ? buffer.readBigInt64LE(offset) : buffer.readBigInt64BE(offset));
      }
      if (descriptor.kind === 'f') {
        if (bytes === 2) return halfToFloat(little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset));
        if (bytes === 4) return little ? buffer.readFloatLE(offset) : buffer.readFloatBE(offset);
        if (bytes === 8) return little ? buffer.readDoubleLE(offset) : buffer.readDoubleBE(offset);
      }
    } catch { return null; }
    return null;
  };
  return { descriptor, read };
}

function imageLayout(shape) {
  if (!Array.isArray(shape)) return null;
  if (shape.length === 2 && shape[0] > 1 && shape[1] > 1) return { layout: 'HW', height: shape[0], width: shape[1], channels: 1, batch: 1 };
  if (shape.length === 3) {
    if ([1, 3, 4].includes(shape[2])) return { layout: 'HWC', height: shape[0], width: shape[1], channels: shape[2], batch: 1 };
    if ([1, 3, 4].includes(shape[0])) return { layout: 'CHW', height: shape[1], width: shape[2], channels: shape[0], batch: 1 };
  }
  if (shape.length === 4) {
    if ([1, 3, 4].includes(shape[3])) return { layout: 'NHWC', height: shape[1], width: shape[2], channels: shape[3], batch: shape[0] };
    if ([1, 3, 4].includes(shape[1])) return { layout: 'NCHW', height: shape[2], width: shape[3], channels: shape[1], batch: shape[0] };
  }
  return null;
}

function npyElementIndex(layout, x, y, c) {
  if (layout.layout === 'HW') return y * layout.width + x;
  if (layout.layout === 'HWC' || layout.layout === 'NHWC') return (y * layout.width + x) * layout.channels + c;
  if (layout.layout === 'CHW' || layout.layout === 'NCHW') return c * layout.height * layout.width + y * layout.width + x;
  return null;
}

function analyzeNpySample(buffer, fileName = 'sample.npy') {
  const parsed = parseNpyAdvanced(buffer);
  if (!parsed) throw new Error('不是可识别的 NPY 文件');
  const reader = makeNumericReader(buffer, parsed);
  const findings = [...(parsed.securityFindings || [])];
  if (!reader) return {
    schema: 'newcyber.ai-npy-sample.v1', fileName, format: parsed.format, header: parsed,
    imageLike: false, numeric: null, preview: null, raster: null, findings,
    notes: ['当前 dtype 无法安全做数值解释；仍保留 NPY header / shape / object dtype 证据。']
  };
  const totalElements = Number(parsed.elementCount);
  if (!Number.isSafeInteger(totalElements) || totalElements <= 0) throw new Error('NPY elementCount 无法安全转换');
  const step = Math.max(1, Math.ceil(totalElements / MAX_NUMERIC_SCAN));
  const sampled = [];
  let nonFinite = 0;
  for (let index = 0; index < totalElements; index += step) {
    const value = reader.read(index);
    if (Number.isFinite(value)) sampled.push(value);
    else nonFinite += 1;
  }
  const sorted = [...sampled].sort((a, b) => a - b);
  const avg = mean(sampled);
  const numeric = {
    sampled: sampled.length,
    samplingStep: step,
    nonFinite,
    min: round(sorted[0]),
    q01: round(quantile(sorted, 0.01)),
    median: round(quantile(sorted, 0.5)),
    q99: round(quantile(sorted, 0.99)),
    max: round(sorted[sorted.length - 1]),
    mean: round(avg),
    std: round(std(sampled, avg))
  };
  if (nonFinite) findings.push({ id: 'npy-non-finite-values', severity: 'medium', title: 'NPY 中存在 NaN / Inf', evidence: { sampledNonFinite: nonFinite, samplingStep: step }, meaning: '非有限数可能影响归一化、阈值校验和模型输入；需要结合服务端解析逻辑验证。' });

  const layout = !parsed.fortranOrder ? imageLayout(parsed.shape) : null;
  if (!layout || layout.width <= 0 || layout.height <= 0 || layout.width * layout.height > 4096 * 4096) {
    return { schema: 'newcyber.ai-npy-sample.v1', fileName, format: parsed.format, header: parsed, imageLike: false, layout, numeric, preview: null, raster: null, findings, notes: [parsed.fortranOrder ? 'Fortran-order NPY 暂不生成图像预览，避免错误解释维度。' : 'shape 不符合常见 HW/HWC/CHW/NHWC/NCHW 图像布局，保留数组统计。'] };
  }

  const q01 = Number.isFinite(numeric.q01) ? numeric.q01 : 0;
  const q99 = Number.isFinite(numeric.q99) ? numeric.q99 : 1;
  let mode = 'robust-minmax';
  let scale = (value) => (value - q01) / Math.max(q99 - q01, 1e-12) * 255;
  if (q01 >= 0 && q99 <= 1.2) { mode = '0..1'; scale = (value) => value * 255; }
  else if (q01 >= -1.2 && q99 <= 1.2) { mode = '-1..1'; scale = (value) => (value + 1) * 127.5; }
  else if (q01 >= 0 && q99 <= 255.5) { mode = '0..255'; scale = (value) => value; }

  const outW = Math.min(128, layout.width);
  const outH = Math.min(128, layout.height);
  const rgba = Buffer.alloc(outW * outH * 4);
  for (let y = 0; y < outH; y += 1) {
    const sy = Math.min(layout.height - 1, Math.floor((y + 0.5) * layout.height / outH));
    for (let x = 0; x < outW; x += 1) {
      const sx = Math.min(layout.width - 1, Math.floor((x + 0.5) * layout.width / outW));
      const values = [];
      for (let c = 0; c < Math.min(layout.channels, 3); c += 1) values.push(reader.read(npyElementIndex(layout, sx, sy, c)));
      if (layout.channels === 1) values.push(values[0], values[0]);
      const offset = (y * outW + x) * 4;
      rgba[offset] = clamp(Math.round(scale(Number.isFinite(values[0]) ? values[0] : 0)), 0, 255);
      rgba[offset + 1] = clamp(Math.round(scale(Number.isFinite(values[1]) ? values[1] : values[0] || 0)), 0, 255);
      rgba[offset + 2] = clamp(Math.round(scale(Number.isFinite(values[2]) ? values[2] : values[0] || 0)), 0, 255);
      rgba[offset + 3] = 255;
    }
  }
  const raster = analyzeRasterImage({ width: outW, height: outH, channels: 4, data: rgba });
  return {
    schema: 'newcyber.ai-npy-sample.v1',
    fileName,
    format: parsed.format,
    header: parsed,
    imageLike: true,
    layout,
    numeric,
    preview: { width: outW, height: outH, normalization: mode, rgbaBase64: rgba.toString('base64') },
    raster,
    findings: [...findings, ...(raster.findings || [])],
    notes: [`图像预览使用 ${mode} 归一化；原始 NPY 不会被执行或 allow_pickle 加载。`, ...(raster.notes || [])]
  };
}

function compareNpySamples(leftBuffer, rightBuffer) {
  const left = parseNpyAdvanced(leftBuffer);
  const right = parseNpyAdvanced(rightBuffer);
  if (!left || !right) throw new Error('NPY 对照需要两个有效 NPY 文件');
  if (JSON.stringify(left.shape) !== JSON.stringify(right.shape)) throw new Error('NPY 对照 shape 不一致');
  if (left.descr !== right.descr) throw new Error('NPY 对照 dtype 不一致');
  const leftReader = makeNumericReader(leftBuffer, left);
  const rightReader = makeNumericReader(rightBuffer, right);
  if (!leftReader || !rightReader) throw new Error('当前 NPY dtype 不支持数值差分');
  const total = Number(left.elementCount);
  if (!Number.isSafeInteger(total) || total <= 0) throw new Error('NPY elementCount 无法安全转换');
  const step = Math.max(1, Math.ceil(total / MAX_NUMERIC_SCAN));
  let compared = 0;
  let l0 = 0;
  let l1 = 0;
  let l2sq = 0;
  let linf = 0;
  for (let index = 0; index < total; index += step) {
    const a = leftReader.read(index);
    const b = rightReader.read(index);
    if (!Number.isFinite(a) || !Number.isFinite(b)) continue;
    const delta = Math.abs(a - b);
    compared += 1;
    if (delta > 1e-12) l0 += 1;
    l1 += delta;
    l2sq += delta ** 2;
    linf = Math.max(linf, delta);
  }
  return {
    schema: 'newcyber.ai-npy-compare.v1',
    shape: left.shape,
    descr: left.descr,
    compared,
    samplingStep: step,
    approximate: step > 1,
    norms: { l0, l1: round(l1), l2: round(Math.sqrt(l2sq)), linf: round(linf), meanAbs: round(l1 / Math.max(compared, 1)) },
    notes: [step > 1 ? `数组过大，按 step=${step} 做确定性采样差分。` : '数组规模允许逐元素精确差分。', 'NPY 差分不加载 Python object / pickle。']
  };
}

module.exports = {
  analyzeRasterImage,
  compareRasterImages,
  analyzeNpySample,
  compareNpySamples,
  frequencyProfile,
  CTF_FREQUENCY_REFERENCE
};
