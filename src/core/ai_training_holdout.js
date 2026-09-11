'use strict';

function text(value){return value==null?'':String(value).trim();}
function sorted(values){return [...new Set(values.map(text).filter(Boolean))].sort((a,b)=>a.localeCompare(b));}
function eventOf(row){return text(row?.event)||'unknown-event';}
function familyOf(row){return text(row?.family)||'unknown-family';}
function challengeOf(row){return text(row?.challenge)||text(row?.rawId)||text(row?.id)||'unknown-challenge';}
function directionOf(row){return text(row?.direction)||'ai-general';}
function challengeKey(row){return `${eventOf(row)}::${challengeOf(row)}`;}

function splitForEvent(rows,heldOutEvent){
  const event=text(heldOutEvent);
  const test=rows.filter((row)=>eventOf(row)===event);
  const train=rows.filter((row)=>eventOf(row)!==event);
  const trainEvents=sorted(train.map(eventOf));
  const testEvents=sorted(test.map(eventOf));
  const trainFamilies=sorted(train.map(familyOf));
  const testFamilies=sorted(test.map(familyOf));
  const knownFamilies=testFamilies.filter((family)=>trainFamilies.includes(family));
  const unseenFamilies=testFamilies.filter((family)=>!trainFamilies.includes(family));
  const trainChallengeKeys=new Set(train.map(challengeKey));
  const leakedChallenges=sorted(test.map(challengeKey).filter((key)=>trainChallengeKeys.has(key)));
  const leakedEvents=testEvents.filter((candidate)=>trainEvents.includes(candidate));
  return {
    heldOutEvent:event,
    trainCases:train.length,
    testCases:test.length,
    trainEvents,
    testEvents,
    trainFamilies,
    testFamilies,
    knownFamilies,
    unseenFamilies,
    mode:unseenFamilies.length?'cross-event-unseen-family':'cross-event-known-family',
    leakage:{event:leakedEvents,challenge:leakedChallenges,clean:leakedEvents.length===0&&leakedChallenges.length===0}
  };
}

function buildDirectionHoldouts(cases=[],direction,options={}){
  const rows=(Array.isArray(cases)?cases:[]).filter((row)=>directionOf(row)===direction);
  const events=sorted(rows.map(eventOf));
  const minTrainEvents=Math.max(1,Number(options.minTrainEvents)||2);
  const plans=events.map((event)=>splitForEvent(rows,event)).filter((plan)=>plan.trainEvents.length>=minTrainEvents&&plan.testCases>0);
  const cleanPlans=plans.filter((plan)=>plan.leakage.clean).length;
  const unseenFamilyPlans=plans.filter((plan)=>plan.unseenFamilies.length>0).length;
  const eligible=events.length>=minTrainEvents+1&&plans.length>0&&cleanPlans===plans.length;
  return {
    direction,
    eligible,
    reason:eligible?null:(events.length<minTrainEvents+1?'insufficient-events':plans.length===0?'no-valid-splits':'leakage-detected'),
    events:events.length,
    families:sorted(rows.map(familyOf)).length,
    cases:rows.length,
    plans,
    summary:{plans:plans.length,cleanPlans,knownFamilyPlans:plans.length-unseenFamilyPlans,unseenFamilyPlans}
  };
}

function analyzeCrossEventHoldout(cases=[],options={}){
  const rows=Array.isArray(cases)?cases:[];
  const requested=Array.isArray(options.directions)&&options.directions.length
    ? sorted(options.directions)
    : sorted(rows.map(directionOf));
  const byDirection=requested.map((direction)=>buildDirectionHoldouts(rows,direction,options));
  const allPlans=byDirection.flatMap((entry)=>entry.plans.map((plan)=>({direction:entry.direction,...plan})));
  return {
    schema:'newcyber.ai-training-holdout.v1',
    summary:{
      directions:byDirection.length,
      eligibleDirections:byDirection.filter((entry)=>entry.eligible).length,
      plans:allPlans.length,
      cleanPlans:allPlans.filter((plan)=>plan.leakage.clean).length,
      unseenFamilyPlans:allPlans.filter((plan)=>plan.unseenFamilies.length>0).length
    },
    byDirection,
    gates:{
      heldOutEventExcludedFromTraining:true,
      challengeLeakageMustBeZero:true,
      minimumTrainingEvents:Math.max(1,Number(options.minTrainEvents)||2)
    },
    note:'Each plan leaves one complete event out of training. A clean split verifies event/challenge isolation; unseen-family plans are stricter probes of generalization than known-family cross-event plans.'
  };
}

module.exports={eventOf,familyOf,challengeOf,challengeKey,splitForEvent,buildDirectionHoldouts,analyzeCrossEventHoldout};
