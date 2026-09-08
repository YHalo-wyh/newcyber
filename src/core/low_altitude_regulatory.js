function lineNumberAt(text,index) { return text.slice(0,Math.max(0,index)).split(/\r?\n/).length; }
function evidenceAt(text,index,radius=260) { return text.slice(Math.max(0,index-100),Math.min(text.length,index+radius)).trim(); }

const SURFACE_PATTERNS = Object.freeze([
  ['flight-permit',/(?:flight[_ -]?(?:permit|plan|approval)|飞行(?:许可|计划|审批))/gi],
  ['airspace',/(?:airspace|geofence|no[_ -]?fly|禁飞区|空域)/gi],
  ['drone-identity',/(?:drone[_ -]?id|uas[_ -]?id|aircraft[_ -]?id|serial[_ -]?number|无人机编号)/gi],
  ['operator',/(?:operator[_ -]?id|pilot[_ -]?id|owner[_ -]?id|飞手|运营人)/gi],
  ['approval-state',/(?:approved|rejected|pending|status|审批状态)/gi]
]);

function scanRegulatoryApi(input) {
  const text=String(input||'');
  if (!text.trim()) throw new Error('请输入 OpenAPI/接口源码/HTTP transcript/JSON 配置');
  const findings=[];
  const surfaces={};

  for (const [name,regex] of SURFACE_PATTERNS) {
    const matches=[...text.matchAll(regex)];
    surfaces[name]=matches.length;
  }

  const idPaths=[...text.matchAll(/(?:GET|POST|PUT|PATCH|DELETE)?\s*["'`]?(\/[A-Za-z0-9_{}\-./]*(?:permit|flight|airspace|drone|uas|operator)[A-Za-z0-9_{}\-./]*)/gi)];
  const authEvidence=/(?:authorization|bearer\s|jwt|oauth|api[_ -]?key|require_auth|isAuthenticated|@login_required|Depends\([^)]*auth)/i.test(text);
  const ownerEvidence=/(?:owner_id|operator_id|pilot_id|user_id|tenant_id|created_by|belongs_to|object.*owner|permission|authorize|acl|rbac)/i.test(text);
  const roleEvidence=/(?:role|admin|reviewer|approver|operator|pilot|rbac|scope|permission)/i.test(text);
  const nonceEvidence=/(?:nonce|jti|idempotency|request[_ -]?id|timestamp|expires?|exp\b|replay)/i.test(text);
  const signatureEvidence=/(?:signature|verify_signature|hmac|ed25519|ecdsa|rsa|public[_ -]?key|signed)/i.test(text);

  for (const match of idPaths.slice(0,80)) {
    const path=match[1];
    if (/\{(?:id|permit_id|flight_id|drone_id|operator_id|airspace_id)\}/i.test(path) && !ownerEvidence) {
      findings.push({
        id:'regulatory-object-authorization-candidate',severity:'high',title:'对象级授权/BOLA 候选',line:lineNumberAt(text,match.index),
        evidence:evidenceAt(text,match.index),
        meaning:`接口 ${path} 暴露对象标识，但当前文本中未找到明确 owner/tenant/object authorization 约束；需核对是否仅凭 ID 读取或修改他人飞行许可/无人机对象。`,
        fix:{target:path,action:'服务端按认证主体重新解析对象归属/租户/角色，不能只信客户端传入 ID。',regression:'更换为其他主体拥有的 object ID 时必须稳定拒绝，且错误响应不泄露对象详情。'}
      });
    }
  }

  if ((surfaces['flight-permit']||surfaces['approval-state']) && !authEvidence) findings.push({
    id:'regulatory-auth-boundary-missing',severity:'high',title:'飞行许可/审批接口未见认证边界',
    evidence:'检测到飞行许可/审批语义，但未发现 Authorization/JWT/OAuth/认证中间件证据。',
    meaning:'这只是静态候选；需要结合路由中间件或网关配置确认真实认证是否在其他层实现。'
  });

  if (roleEvidence && /(approved|rejected|approval|status|审批)/i.test(text) && !/(?:require.*(?:admin|reviewer|approver)|hasRole|has_role|scope.*(?:approve|review)|permission.*(?:approve|review))/i.test(text)) findings.push({
    id:'regulatory-approval-role-candidate',severity:'medium',title:'审批状态变更缺少明确角色约束候选',
    evidence:'存在角色/审批语义，但未识别到 approve/review 专项角色或 scope 校验。',
    meaning:'重点核对普通 operator/pilot 是否能直接写 approved/status 字段。'
  });

  const massAssignment=[...text.matchAll(/\b(?:approved|status|role|owner_id|operator_id|pilot_id|tenant_id|airspace_id)\b/gi)];
  const genericBody=/(?:request\.json|request\.body|req\.body|payload|body\s*=|\.dict\(\)|model_dump\(\)|\*\*request)/i.test(text);
  if (massAssignment.length>=2 && genericBody && /(?:create|update|patch|save|insert|upsert)/i.test(text)) findings.push({
    id:'regulatory-mass-assignment-candidate',severity:'medium',title:'许可/身份字段 Mass Assignment 候选',
    evidence:'请求体通用映射与 approved/status/role/owner 等敏感字段同时出现。',
    meaning:'检查服务端 schema 是否允许客户端直接覆盖审批状态、角色或对象归属。'
  });

  if ((surfaces['flight-permit']||surfaces.airspace) && /(lat(?:itude)?|lon(?:gitude)?|lng|alt(?:itude)?|start_time|end_time|radius|polygon)/i.test(text)) {
    const bounds=/(?:-90|90|-180|180|max_alt|min_alt|range|between|geofence.*contains|polygon.*contains|within|start.*<.*end|end.*>.*start)/i.test(text);
    if (!bounds) findings.push({
      id:'regulatory-geo-time-validation-candidate',severity:'medium',title:'空域/时间范围校验不足候选',
      evidence:'检测到经纬度/高度/起止时间字段，但未识别到明显边界或空间包含校验。',
      meaning:'核对 NaN/Infinity、越界坐标、负高度、start>end、超长许可窗口以及 polygon 边界条件。'
    });
  }

  if (/(?:approve|permit|issue|grant|submit|activate|takeoff)/i.test(text) && !nonceEvidence) findings.push({
    id:'regulatory-replay-candidate',severity:'medium',title:'许可/审批动作缺少防重放证据',
    evidence:'存在许可签发/审批/激活动作，未识别 nonce/jti/idempotency/timestamp/expiry。',
    meaning:'对签名许可、二维码/令牌或提交动作检查重复请求是否可以重复生效。'
  });

  if (/(?:permit[_ -]?token|flight[_ -]?token|qr|license|approval[_ -]?code)/i.test(text) && !signatureEvidence) findings.push({
    id:'regulatory-permit-integrity-candidate',severity:'medium',title:'许可凭证完整性保护候选不足',
    evidence:'存在许可 token/code/QR 语义，但未识别签名/HMAC/公钥验证。',
    meaning:'若凭证内容由客户端携带，需确认服务端是否签名验证且绑定主体、无人机、空域、时间窗。'
  });

  const endpoints=idPaths.slice(0,120).map((m)=>({ line:lineNumberAt(text,m.index), path:m[1] }));
  const nextActions=[];
  if (findings.some((x)=>x.id==='regulatory-object-authorization-candidate')) nextActions.push('优先画 identity → operator/drone → flight permit → airspace 的对象归属链，再逐接口核对 read/write 权限。');
  if (findings.some((x)=>x.id==='regulatory-replay-candidate')) nextActions.push('对提交/审批/许可 token 建状态机：issued → used/revoked/expired，确认重复请求不能二次生效。');
  if (surfaces.airspace) nextActions.push('把经纬度、高度、半径/polygon 和时间窗统一做边界检查，特别关注 NaN/Infinity、反向时间窗与边界点。');

  return {
    surfaces,
    authEvidence,
    ownerEvidence,
    roleEvidence,
    nonceEvidence,
    signatureEvidence,
    endpoints,
    findings,
    summary:{ high:findings.filter((x)=>x.severity==='high').length, medium:findings.filter((x)=>x.severity==='medium').length, info:findings.filter((x)=>x.severity==='info').length },
    nextActions,
    notes:['这是离线静态/Transcript 审计；未看到某个校验不等于线上一定缺失，网关/中间件/数据库策略必须纳入复核。','所有 finding 都保持“候选”语义，只有通过实际授权边界/状态机验证后才升级为已确认问题。']
  };
}

module.exports={ scanRegulatoryApi };
