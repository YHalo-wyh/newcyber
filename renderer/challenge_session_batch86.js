(() => {
  if(typeof workspaceView!=='function'||typeof render!=='function')return;
  const previousWorkspaceView=workspaceView;

  function triggerNeed(auto){
    if(!auto||auto.status!=='candidate'||!auto.result)return null;
    return{
      code:'TRIGGER_VERIFIER_OR_HOLDOUT',kind:'file-or-context',title:'补 reward/checker 或独立 holdout 结果',
      why:'Universal Trigger 候选已经从多组 Prompt 记录中排出来；现在只差题目自己的判定逻辑或一份未参与排名的 holdout 结果。',
      detail:'优先提供 checker.py / scorer.py / reward validation script；没有判题脚本时，提供新的 prompt_id + success/reward 记录即可。',
      accepts:['checker.py / scorer.py / reward validation script','holdout_trigger_results.csv / json'],action:'add-files'
    };
  }

  workspaceView=function batch86Workspace(){
    const session=state.workspace?.challengeSession;const auto=state.workspace?.aiUniversalTriggerAutopilot;
    if(!session||session.status==='solved'||state.workspace?.submissionAutopilot?.status==='formatted')return previousWorkspaceView();
    const need=triggerNeed(auto);if(!need)return previousWorkspaceView();
    const previous=session.nextInput;session.nextInput=need;
    try{return previousWorkspaceView();}finally{session.nextInput=previous;}
  };
  render();
})();
