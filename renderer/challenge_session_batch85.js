(() => {
  if(typeof workspaceView!=='function'||typeof render!=='function')return;
  const previousWorkspaceView=workspaceView;

  function verifierNeed(auto){
    if(!auto||auto.status!=='formatted'||!auto.result)return null;
    return {
      code:'SUBMISSION_VERIFIER_MISSING',kind:'file-or-context',title:'补题目 checker / verifier / scorer',
      why:`提交内容已经按 ${auto.result.template||'题目模板'} 自动生成；现在只差题目自己的判定逻辑确认是否可提交。`,
      detail:'直接提供 checker.py、verifier.py、scorer.py 或本地 judge。NewCyber 会自动重新分析并尝试闭环，不需要手工复制候选到工具里。',
      accepts:['checker.py / verifier.py / scorer.py','local judge / validation script'],action:'add-files'
    };
  }

  workspaceView=function batch85Workspace(){
    const session=state.workspace?.challengeSession;const auto=state.workspace?.submissionAutopilot;
    if(!session||session.status==='solved')return previousWorkspaceView();
    const need=verifierNeed(auto);if(!need)return previousWorkspaceView();
    const previous=session.nextInput;session.nextInput=need;
    try{return previousWorkspaceView();}finally{session.nextInput=previous;}
  };
  render();
})();
