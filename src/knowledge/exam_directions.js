module.exports=[
  {
    id:'ai.model-extraction',track:'ai',domain:'人工智能',title:'黑盒模型窃取 / Model Extraction',
    tags:['model-stealing','model-extraction','soft-label','logits','probabilities','substitute-model','fidelity'],
    summary:'模型窃取题先恢复 query→output transcript、输出精度、随机性与类别覆盖，再在独立 holdout 上评估 substitute 与目标模型输出的一致率。完整概率/logit 会显著增加边界信息。',
    evidence:['API 返回完整 probability/logit','重复 query 输出稳定','存在大规模 query transcript'],
    prerequisites:['只使用赛题/授权 API 或已有 transcript','复现真实 preprocessing'],
    verify:['独立 holdout 上报告 fidelity/agreement','单独统计 victim query 数量','重复 query 估计随机性'],
    falsePositives:['训练准确率高不代表成功抽取目标模型','同一 transcript 上训练再评分会自证'],
    actions:['先审计输出暴露','按类别/置信区间检查 query 覆盖','构造离线 substitute 验证'],
    mutations:['top1-only','rounded-confidence','full-probability','stochastic-output','class-coverage-gap']
  },
  {
    id:'ai.ocr-extraction',track:'ai',domain:'人工智能',title:'OCR 黑盒模型窃取',
    tags:['ocr','model-extraction','char-confidence','bounding-box','layout','cer','wer','fidelity'],
    summary:'OCR 黑盒题除了最终文本，还要审计字符/词级置信度、logit、检测框和版式信息。替代模型必须按源图像/文档分组划分独立 holdout，并分别报告文本与布局 fidelity。',
    evidence:['image_id→recognized text transcript','char/word confidence','bounding boxes/polygons','重复 OCR query'],
    prerequisites:['只使用赛题/授权 transcript','复现 resize/normalize/tokenization'],
    verify:['文本 exact agreement/CER/WER','检测框 IoU/匹配率','单独统计 victim query 数量'],
    falsePositives:['字符集覆盖高不代表模型结构已恢复','训练集 OCR 准确率不能代表黑盒 fidelity'],
    actions:['统计字符覆盖','比较 final-text 与 soft-label 暴露收益','按文档来源隔离 holdout'],
    mutations:['char-confidence-disabled','box-quantization','charset-gap','stochastic-ocr','layout-only']
  },
  {
    id:'ai.model-inversion',track:'ai',domain:'人工智能',title:'模型反演 / 输入重建',
    tags:['model-inversion','reconstruction','embedding','gradient','logits','privacy'],
    summary:'模型反演关注从概率、logit、embedding、gradient 等输出恢复输入特征或代表性样本，与 membership inference 不同。重建结果应同时用数值与任务指标验证。',
    evidence:['完整概率/logit','embedding/hidden state','gradient','reference/reconstructed pair'],
    prerequisites:['确认输出跨越真实信任边界','明确 preprocessing 和 reference 语义'],
    verify:['MAE/L2/L∞/cosine','图像场景补 SSIM/PSNR','独立样本验证'],
    falsePositives:['本地调试 tensor 不等于 API 泄露','视觉相似不等于隐私恢复'],
    actions:['收敛输出 schema','比较 top1/topk/full-vector 对重建效果影响'],
    mutations:['embedding-dimension','logit-rounding','gradient-disabled','reference-shift']
  },
  {
    id:'lowalt.regulatory-api',track:'lowalt',domain:'低空经济',title:'低空监管 / 飞行许可 API 安全',
    tags:['utm','u-space','flight-permit','airspace','bola','idor','approval','replay','geofence'],
    summary:'监管系统题重点不是普通 Web 关键字，而是 identity→operator/drone→flight permit→airspace→approval 的对象与状态机边界。优先查 BOLA、审批角色、重放、坐标/高度/时间范围和许可凭证完整性。',
    evidence:['飞行许可/空域 API','对象 ID 路由','approved/status 字段','permit token/QR'],
    prerequisites:['能够看到 API/源码/OpenAPI/HTTP transcript'],
    verify:['跨主体 object ID 稳定拒绝','重复提交不能二次生效','许可绑定无人机/主体/空域/时间窗'],
    falsePositives:['认证可能在网关/中间件实现','文本未见 owner check 不等于线上必缺失'],
    actions:['建立对象归属图','恢复审批状态机','检查地理与时间边界'],
    mutations:['other-owner-id','role-change','approval-replay','nan-coordinate','reversed-time-window']
  },
  {
    id:'lowalt.gnss-integrity',track:'lowalt',domain:'低空经济',title:'GNSS / GPS 欺骗与干扰证据链',
    tags:['gnss','gps','nmea','gga','rmc','gsv','sdr','fft','jamming','spoofing','snr'],
    summary:'GNSS 题分两层：导航数据层用 NMEA/飞控日志检查 checksum、时间、位置速度、卫星/SNR 一致性；RF 层用 SDR/FFT 看窄带峰与宽带噪声抬升。任何单层异常都不应直接宣称 spoofing。',
    evidence:['GGA/RMC/GSV/GSA','GPS_RAW_INT','FFT/功率谱','SNR/CN0'],
    prerequisites:['统一时间轴','知道采集频段/采样设置或至少有频率坐标'],
    verify:['NMEA checksum','位置隐含速度','多源 GPS 交叉','正常环境/50Ω 基线频谱'],
    falsePositives:['遮挡/多径可造成定位质量下降','LO 泄漏/AGC 可制造频谱峰'],
    actions:['NMEA→MAVLink/ULog 对齐','按 PRN/SNR 聚合','异常 FFT 与接收机状态交叉'],
    mutations:['time-rollback','position-jump','satellite-count-jump','narrowband-peak','wideband-noise-rise']
  },
  {
    id:'lowalt.datalink-passive',track:'lowalt',domain:'低空经济',title:'无人机数据链 / Lightbridge / OcuSync 被动证据',
    tags:['datalink','lightbridge','ocusync','dji','control-link','telemetry','media-flow','udp'],
    summary:'专有数据链未知时先做被动流量画像：厂商字符串、主机对、UDP 包长/速率、控制小包与高带宽媒体流组合，再决定是否需要私有协议适配器。不能仅凭高带宽 UDP 就声称 OcuSync/Lightbridge。',
    evidence:['DJI/Lightbridge/OcuSync 明确字符串','同主机对控制与媒体流','未知高带宽 UDP'],
    prerequisites:['有离线 PCAP/PCAPNG 或固件内恢复抓包'],
    verify:['明确 vendor/protocol evidence','固定头/计数器/长度分布','与 MAVLink/RTSP/RTP 时间线交叉'],
    falsePositives:['普通 RTP/媒体流可呈高带宽 UDP','端口号本身不足以识别厂商协议'],
    actions:['按 flow 聚合','分析固定头/计数器/熵','关联断链与控制事件'],
    mutations:['vendor-string-absent','unknown-high-rate-flow','control-media-pair','flow-direction-change']
  },
  {
    id:'lowalt.firmware-update-chain',track:'lowalt',domain:'低空经济',title:'飞控/机载固件升级信任链',
    tags:['firmware-update','ota','signature','rollback','manifest','flash','bootloader','sysupgrade'],
    summary:'升级安全必须沿 download→manifest→signature/hash→extract/decrypt→flash→boot slot/rollback 全链审计。仅存在 SHA256 或 verify 调用不等于最终写入字节已被可信发布者绑定。',
    evidence:['升级脚本/manifest','verify_signature','mtd/flashcp/sysupgrade','version/rollback index'],
    prerequisites:['能定位最终写入动作和输入来源'],
    verify:['签名覆盖最终写入内容','公钥来源可信','旧版合法签名镜像不能任意回滚','解包后路径不可逃逸'],
    falsePositives:['校验可能在 bootloader/secure element 实现','字符串命中不等于真实控制流可达'],
    actions:['画升级数据流','绑定每阶段 hash','检查 A/B slot 与 recovery 差异'],
    mutations:['plain-http','tls-insecure','signature-before-transform','downgrade','archive-path-change']
  },
  {
    id:'lowalt.rtp-video-recovery',track:'lowalt',domain:'低空经济',title:'RTP/H264/H265 图传恢复与中断分析',
    tags:['rtp','rtsp','h264','h265','fu-a','stap-a','aggregation-packet','annex-b','video','ssrc','sequence'],
    summary:'图传抓包先按 RTP SSRC/PT/sequence 建会话；H264 支持 single NAL/STAP-A/FU-A，H265 支持 single NAL/AP/FU，并重组 Annex-B。sequence gap 与未闭合 FU 必须标记 partial。',
    evidence:['RTP v2 header','H264/H265 NAL/FU','RTSP endpoint','VPS/SPS/PPS'],
    prerequisites:['抓包包含未加密 RTP payload'],
    verify:['RTP sequence 连续','FU start/end 闭合','导出 Annex-B 可由 ffmpeg/ffplay 复核'],
    falsePositives:['动态 RTP payload 不一定是 H264/H265','抓包缺包不一定代表真实链路中断'],
    actions:['按 SSRC/PT 重组','导出 H264/H265 artifact','与 RTSP TEARDOWN/网络异常对齐'],
    mutations:['rtp-gap','fu-fragment','ssrc-change','payload-type-change','codec-switch']
  }
];
