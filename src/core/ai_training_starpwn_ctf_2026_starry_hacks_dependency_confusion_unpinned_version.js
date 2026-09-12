'use strict';

const CORPUS_ENTRY={
  "id": "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-synthetic-regression",
  "event": "STARPWN CTF 2026",
  "challenge": "Starry hacks",
  "direction": "infra-supply-chain",
  "family": "dependency-confusion-unpinned-version",
  "evaluator": "ai-supply-chain",
  "caseType": "public-training",
  "provenance": {
    "title": "STARPWN CTF 2026 — Starry hacks public writeup",
    "url": "https://github.com/JonghoMoon/STARPWN-2026-Writeup/blob/619d5555dbaeefe9de962edc1e2cc2879692a710/Space_Communication_and_RF/Starry_hacks/README.md",
    "kind": "writeup",
    "evidenceLevel": "writeup-specific"
  },
  "coverage": "The public writeup documents a Python dependency constrained only by a lower bound, an artifact-upload path that installs a replacement package with pip, and higher-version package substitution at the dependency trust boundary.",
  "trainingPolicy": "public-evidence-plus-synthetic-regression-only",
  "limitation": "Synthetic fixtures encode only dependency-resolution structure. They contain no original challenge secret, flag, hidden answer, unpublished trigger, private attachment, or malicious package payload.",
  "fixtureIds": [
    "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-positive",
    "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-negative",
    "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-control"
  ]
};
const FIXTURES=[
  {
    "id": "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-positive",
    "role": "positive",
    "synthetic": true,
    "payload": "cubesat-upstream-driver>=1.0.0",
    "expected": {
      "status": "finding",
      "predicate": "A lower-bound-only package constraint must be reported as dependency-not-locked.",
      "assertions": [
        {"path":"findings.0.id","op":"eq","value":"dependency-not-locked"},
        {"path":"summary.info","op":"gte","value":1}
      ]
    }
  },
  {
    "id": "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-negative",
    "role": "negative",
    "synthetic": true,
    "payload": "cubesat-upstream-driver==1.2.3",
    "expected": {
      "status": "non-finding",
      "predicate": "An exact version pin must not be reported as dependency-not-locked.",
      "assertions": [
        {"path":"findings","op":"length-eq","value":0},
        {"path":"summary.info","op":"eq","value":0}
      ]
    }
  },
  {
    "id": "starpwn-ctf-2026-starry-hacks-dependency-confusion-unpinned-version-control",
    "role": "control",
    "synthetic": true,
    "payload": "# synthetic pinned control\ncubesat-upstream-driver==1.2.3",
    "expected": {
      "status": "non-finding",
      "predicate": "A pinned control with unrelated comments must remain non-finding, isolating the version constraint as the signal.",
      "assertions": [
        {"path":"findings","op":"length-eq","value":0},
        {"path":"summary.info","op":"eq","value":0}
      ]
    }
  }
];

function getTrainingCorpus(){return [CORPUS_ENTRY];}
function getSyntheticFixtures(){return FIXTURES;}

module.exports={CORPUS_ENTRY,FIXTURES,getTrainingCorpus,getSyntheticFixtures};
