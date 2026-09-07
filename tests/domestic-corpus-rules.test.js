const test = require('node:test');
const assert = require('node:assert/strict');
const { auditAiChallengeSource } = require('../src/core/ai_source');
const { auditSolanaAnchor, inspectAnchorToml } = require('../src/core/solana');

// Regression source: SUCTF 2026 / SU_easyLLM.
test('SUCTF 2026 SU_easyLLM: detect LLM output -> SHA256 -> AES key chain', () => {
  const source = `
SYSTEM_PROMPT = "You are a password generator"
TEMPERATURE = 0.28

def call_glm_once():
    r = requests.post("https://api.z.ai/api/paas/v4/chat/completions", json={"temperature": TEMPERATURE})
    return r.json()["choices"][0]["message"]["content"].strip()

def derive_key_from_llm(pw):
    return hashlib.sha256(pw.encode("utf-8")).digest()[:16]

LLM_PASSWORD = call_glm_once()
KEY = derive_key_from_llm(LLM_PASSWORD, key_len=16)
CIPHERTEXT = aes_cbc_encrypt(KEY, IV, FLAG.encode("utf-8"))
return JSONResponse({"system_prompt": SYSTEM_PROMPT, "temperature": TEMPERATURE})
`;
  const result = auditAiChallengeSource(source);
  assert.ok(result.findings.some((item) => item.id === 'llm-derived-crypto-key'));
  assert.ok(result.findings.some((item) => item.id === 'llm-replay-parameters-exposed'));
  assert.ok(result.llmCrypto);
  assert.ok(result.llmCrypto.temperatures.includes(0.28));
});

// Regression source: USTC Hackergame 2023 / 小型大语言模型星球.
test('Hackergame 2023 small LLM planet: extract target-output oracle and generation constraints', () => {
  const source = `
model = AutoModelForCausalLM.from_pretrained("roneneldan/TinyStories-33M").eval()
tokenizer = AutoTokenizer.from_pretrained("roneneldan/TinyStories-33M")

def check_message(message):
    if len(message) > 200:
        return False, "too long"

def check_response(message, response):
    if "you are smart" in response:
        pass
    if len(message) <= 7 and "accepted" in response:
        pass
    if len(message) <= 100 and "hackergame" in response:
        pass
    if len(message) <= 200 and "🐮" in response:
        pass

def predict(message):
    model_inputs = tokenizer.encode(message, return_tensors="pt")
    model_outputs = model.generate(
        model_inputs,
        max_new_tokens=30,
        num_beams=1,
        pad_token_id=tokenizer.eos_token_id,
    )
    return model_outputs
`;
  const result = auditAiChallengeSource(source);
  assert.ok(result.generationChallenge);
  assert.deepEqual(result.generationChallenge.models, ['roneneldan/TinyStories-33M']);
  assert.equal(result.generationChallenge.generation.maxNewTokens, 30);
  assert.equal(result.generationChallenge.generation.numBeams, 1);
  assert.equal(result.generationChallenge.globalInputMaxLength, 200);
  assert.equal(result.generationChallenge.deterministicGreedy, true);
  assert.deepEqual(result.generationChallenge.targets.map((item) => [item.target, item.inputMaxLength]), [
    ['you are smart', null],
    ['accepted', 7],
    ['hackergame', 100],
    ['🐮', 200]
  ]);
  assert.ok(result.findings.some((item) => item.id === 'target-output-oracle'));
});

// Regression source: SUCTF 2025 / Onchain_Checkin.
test('SUCTF 2025 Onchain_Checkin: extract Anchor program id and account constraints', () => {
  const source = `
use anchor_lang::prelude::*;
declare_id!("SUCTF2Q25DnchainCheckin11111111111111111111");
#[program]
pub mod checkin {
  pub fn flag2(ctx: Context<Checkin>) -> Result<()> { ctx.accounts.checkin() }
}
#[derive(Accounts)]
pub struct Checkin<'info> {
  #[account(mut)] pub deployer: Signer<'info>,
  pub account2: AccountInfo<'info>,
  pub account3: AccountInfo<'info>,
  #[account(init, payer = deployer, seeds = [b"checkin_state"], bump)]
  pub checkin_state: Account<'info, CheckinState>,
}
impl<'info> Checkin<'info> {
  pub fn checkin(&mut self) -> Result<()> {
    self.checkin_state.flag3 = self.account3.key();
    msg!("flag1");
    Ok(())
  }
}
`;
  const result = auditSolanaAnchor(source);
  assert.ok(result);
  assert.equal(result.programId, 'SUCTF2Q25DnchainCheckin11111111111111111111');
  assert.ok(result.pdaSeeds.includes('checkin_state'));
  assert.ok(result.rawAccountInfos.some((item) => item.name === 'account3'));
  assert.ok(result.findings.some((item) => item.id === 'raw-account-key-to-state'));
  assert.ok(result.messages.includes('flag1'));
});

test('SUCTF 2025 Onchain_Checkin: parse pinned Anchor.toml', () => {
  const config = inspectAnchorToml(`
[toolchain]
solana_version = "2.0.20"
anchor_version = "0.30.1"
[provider]
cluster = "devnet"
`);
  assert.deepEqual(config, {
    format: 'Anchor.toml',
    solanaVersion: '2.0.20',
    anchorVersion: '0.30.1',
    cluster: 'devnet'
  });
});
