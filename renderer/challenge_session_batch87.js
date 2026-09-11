(() => {
  if(typeof workspaceView!=='function'||typeof render!=='function')return;
  const previousWorkspaceView=workspaceView;

  function fingerprintNeed(auto){
    if(!auto||auto.status!=='candidate'||!auto.result)return null;
    return{
      code:'MODEL_FINGERPRINT_VERIFIER_OR_HOLDOUT',kind:'file-or-context',title:'补 checker 或独立 fingerprint holdout',
      why:'目标模型候选已经按 victim↔candidate 输出一致性排出来；现在只差题目判定逻辑或一组未参与排名的新 query。',
      detail:'优先提供 checker.py / verifier.py / scorer.py；没有判题脚本时，提供 fingerprint_holdout.csv/json，包含 candidate_model、query_id，以及 victim/candidate label 或概率/logit。',
      accepts:['checker.py / verifier.py / scorer.py','fingerprint_holdout.csv / json'],action:'add-files'
    };
  }

  workspaceView=function batch87Workspace(){
    const session=state.workspace?.challengeSession;const auto=state.workspace?.aiModelFingerprintAutopilot;
    if(!session||session.status==='solved'||state.workspace?.submissionAutopilot?.status==='formatted')return previousWorkspaceView();
    const need=fingerprintNeed(auto);if(!need)return previousWorkspaceView();
    const previous=session.nextInput;session.nextInput=need;
    try{return previousWorkspaceView();}finally{session.nextInput=previous;}
  };
  render();
})();
