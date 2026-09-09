'use strict';

const DEFAULT_MAX_ENUMERATIONS = 2_000_000;
const MAX_ROWS = 4096;
const MAX_DIMENSION = 32;
const MAX_SAFE_MODULUS = 10_000_000;

function mod(value, q) {
  const result = value % q;
  return result < 0 ? result + q : result;
}

function centered(value, q) {
  const reduced = mod(value, q);
  return reduced > q / 2 ? reduced - q : reduced;
}

function egcd(a, b) {
  let oldR = a;
  let r = b;
  let oldS = 1;
  let s = 0;
  while (r !== 0) {
    const quotient = Math.floor(oldR / r);
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  return [oldR, oldS];
}

function inverseMod(value, q) {
  const reduced = mod(value, q);
  const [gcd, inverse] = egcd(reduced, q);
  return gcd === 1 ? mod(inverse, q) : null;
}

function assertSystem(A, b, q, bound) {
  if (!Array.isArray(A) || !A.length || !Array.isArray(A[0]) || !A[0].length) throw new Error('A 必须是非空二维整数矩阵');
  const rows = A.length;
  const cols = A[0].length;
  if (rows > MAX_ROWS) throw new Error(`方程数量超过 ${MAX_ROWS} 上限`);
  if (cols > MAX_DIMENSION) throw new Error(`secret 维数超过 ${MAX_DIMENSION} 上限`);
  if (rows < cols) throw new Error('方程数量少于 secret 维数，当前 bounded solver 不尝试欠定系统');
  if (!A.every((row) => Array.isArray(row) && row.length === cols && row.every(Number.isSafeInteger))) throw new Error('A 必须是等宽安全整数矩阵');
  if (!Array.isArray(b) || b.length !== rows || !b.every(Number.isSafeInteger)) throw new Error('b 必须是与 A 行数一致的安全整数数组');
  if (!Number.isSafeInteger(q) || q < 2 || q > MAX_SAFE_MODULUS) throw new Error(`modulus 需要是 2..${MAX_SAFE_MODULUS} 的安全整数`);
  if (!Number.isSafeInteger(bound) || bound < 0 || bound > 16) throw new Error('noise bound 需要是 0..16 的整数');
  return { rows, cols };
}

function invertMatrix(matrix, q) {
  const n = matrix.length;
  if (!n || matrix.some((row) => row.length !== n)) return null;
  const augmented = matrix.map((row, rowIndex) => [
    ...row.map((value) => mod(value, q)),
    ...Array.from({ length: n }, (_, columnIndex) => rowIndex === columnIndex ? 1 : 0)
  ]);

  for (let column = 0; column < n; column += 1) {
    let pivot = column;
    while (pivot < n && inverseMod(augmented[pivot][column], q) == null) pivot += 1;
    if (pivot >= n) return null;
    [augmented[column], augmented[pivot]] = [augmented[pivot], augmented[column]];

    const inverse = inverseMod(augmented[column][column], q);
    if (inverse == null) return null;
    for (let index = 0; index < 2 * n; index += 1) augmented[column][index] = mod(augmented[column][index] * inverse, q);

    for (let row = 0; row < n; row += 1) {
      if (row === column) continue;
      const factor = augmented[row][column];
      if (!factor) continue;
      for (let index = 0; index < 2 * n; index += 1) {
        augmented[row][index] = mod(augmented[row][index] - factor * augmented[column][index], q);
      }
    }
  }
  return augmented.map((row) => row.slice(n));
}

function chooseInvertibleRows(A, q) {
  const dimension = A[0].length;
  const basis = [];
  const selectedRows = [];

  for (let rowIndex = 0; rowIndex < A.length; rowIndex += 1) {
    const work = A[rowIndex].map((value) => mod(value, q));
    for (const basisRow of basis) {
      const factor = work[basisRow.pivot];
      if (!factor) continue;
      for (let column = basisRow.pivot; column < dimension; column += 1) {
        work[column] = mod(work[column] - factor * basisRow.row[column], q);
      }
    }

    let pivot = -1;
    for (let column = 0; column < dimension; column += 1) {
      if (work[column] && inverseMod(work[column], q) != null) {
        pivot = column;
        break;
      }
    }
    if (pivot < 0) continue;

    const inverse = inverseMod(work[pivot], q);
    for (let column = pivot; column < dimension; column += 1) work[column] = mod(work[column] * inverse, q);
    for (const basisRow of basis) {
      const factor = basisRow.row[pivot];
      if (!factor) continue;
      for (let column = pivot; column < dimension; column += 1) {
        basisRow.row[column] = mod(basisRow.row[column] - factor * work[column], q);
      }
    }

    basis.push({ pivot, row: work });
    basis.sort((left, right) => left.pivot - right.pivot);
    selectedRows.push(rowIndex);
    if (basis.length === dimension) {
      const rows = selectedRows.slice(-dimension);
      const inverseMatrix = invertMatrix(rows.map((index) => A[index]), q);
      if (inverseMatrix) return { rows, inverseMatrix };
    }
  }
  return null;
}

function boundedPower(base, exponent, cap) {
  let value = 1;
  for (let index = 0; index < exponent; index += 1) {
    value *= base;
    if (value > cap) return cap + 1;
  }
  return value;
}

function dotMod(row, vector, q) {
  let value = 0;
  for (let index = 0; index < row.length; index += 1) {
    value = mod(value + mod(row[index], q) * mod(vector[index], q), q);
  }
  return value;
}

function solveExactModular(A, b, q) {
  const { rows, cols } = assertSystem(A, b, q, 0);
  const selected = chooseInvertibleRows(A, q);
  if (!selected) return { status: 'no-invertible-subsystem', rows, dimension: cols, modulus: q, bound: 0, candidates: [] };
  const selectedB = selected.rows.map((index) => mod(b[index], q));
  const secret = selected.inverseMatrix.map((row) => dotMod(row, selectedB, q));
  const residuals = A.map((row, index) => centered(b[index] - dotMod(row, secret, q), q));
  const valid = residuals.every((value) => value === 0);
  return {
    status: valid ? 'unique' : 'none',
    method: 'exact-modular-linear',
    rows,
    dimension: cols,
    modulus: q,
    bound: 0,
    selectedRows: selected.rows,
    enumerations: 1,
    candidates: valid ? [{ secretMod: secret, secretSigned: secret.map((value) => centered(value, q)), residuals }] : []
  };
}

function solveBoundedModular(A, b, q, bound, options = {}) {
  const { rows, cols } = assertSystem(A, b, q, bound);
  if (bound === 0) return solveExactModular(A, b, q);

  const maxEnumerations = Math.max(1, Math.min(Number(options.maxEnumerations) || DEFAULT_MAX_ENUMERATIONS, 20_000_000));
  const selected = chooseInvertibleRows(A, q);
  if (!selected) {
    return {
      status: 'no-invertible-subsystem', method: 'bounded-error-enumeration', rows, dimension: cols, modulus: q, bound,
      candidates: [], notes: ['没有找到可逆的 n×n 方程子集；当前版本不对该环上的非单位 pivot 做猜测。']
    };
  }

  const requestedEnumerations = boundedPower(2 * bound + 1, cols, maxEnumerations);
  if (requestedEnumerations > maxEnumerations) {
    return {
      status: 'search-too-large', method: 'bounded-error-enumeration', rows, dimension: cols, modulus: q, bound,
      selectedRows: selected.rows, enumerationsRequested: `>${maxEnumerations}`, limit: maxEnumerations, candidates: [],
      notes: ['枚举预算不足。工具不会为了“自动解题”静默扩大到不可控搜索；后续可切换 LLL/BKZ 或外部 lattice backend。']
    };
  }

  const selectedB = selected.rows.map((index) => mod(b[index], q));
  const baseSecret = selected.inverseMatrix.map((row) => dotMod(row, selectedB, q));
  const errorVector = Array(cols).fill(-bound);
  const candidates = [];
  const seen = new Set();
  let enumerations = 0;

  const verifyCandidate = () => {
    enumerations += 1;
    const secret = baseSecret.slice();
    for (let secretIndex = 0; secretIndex < cols; secretIndex += 1) {
      let correction = 0;
      for (let errorIndex = 0; errorIndex < cols; errorIndex += 1) {
        correction = mod(correction + selected.inverseMatrix[secretIndex][errorIndex] * mod(errorVector[errorIndex], q), q);
      }
      secret[secretIndex] = mod(secret[secretIndex] - correction, q);
    }

    const residuals = [];
    for (let rowIndex = 0; rowIndex < rows; rowIndex += 1) {
      const residual = centered(b[rowIndex] - dotMod(A[rowIndex], secret, q), q);
      if (Math.abs(residual) > bound) return;
      residuals.push(residual);
    }

    const key = secret.join(',');
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({
      secretMod: secret,
      secretSigned: secret.map((value) => centered(value, q)),
      residuals,
      maxAbsResidual: Math.max(...residuals.map((value) => Math.abs(value)), 0)
    });
  };

  const recurse = (index) => {
    if (candidates.length > 32) return;
    if (index === cols) {
      verifyCandidate();
      return;
    }
    for (let value = -bound; value <= bound; value += 1) {
      errorVector[index] = value;
      recurse(index + 1);
    }
  };
  recurse(0);

  return {
    status: candidates.length === 1 ? 'unique' : candidates.length ? 'ambiguous' : 'none',
    method: 'bounded-error-enumeration',
    rows,
    dimension: cols,
    modulus: q,
    bound,
    selectedRows: selected.rows,
    enumerations,
    candidates,
    notes: [
      `只枚举一个可逆 ${cols}×${cols} 子系统的 bounded error，再用全部 ${rows} 条方程验证。`,
      '候选只有在所有 residual 都落入公开/提取出的 noise bound 时才保留。'
    ]
  };
}

module.exports = {
  DEFAULT_MAX_ENUMERATIONS,
  mod,
  centered,
  inverseMod,
  invertMatrix,
  chooseInvertibleRows,
  solveExactModular,
  solveBoundedModular
};