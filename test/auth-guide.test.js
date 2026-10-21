import assert from 'node:assert/strict';
import { test } from 'node:test';
import { authenticationGuide, shellQuote } from '../public/auth-guide.js';

test('copyable MFA commands quote profile and Region as shell arguments', () => {
  assert.equal(shellQuote("team's-role"), `'team'"'"'s-role'`);
  const guide = authenticationGuide('role-mfa', "team's-role", 'us-east-1');
  assert.equal(guide.command,
    `aws sts get-caller-identity --profile 'team'"'"'s-role' --region 'us-east-1'`);
  assert.equal(guide.command.includes('--token-code'), false);
});

test('authentication guides use the correct AWS CLI flow for each profile type', () => {
  assert.equal(authenticationGuide('sso', 'team', 'us-east-1').command, "aws sso login --profile 'team'");
  assert.equal(authenticationGuide('login', 'team', 'us-east-1').command, "aws login --profile 'team'");
  assert.equal(authenticationGuide('iam-user-mfa', 'team', 'us-east-1').command,
    "aws configure mfa-login --profile 'team'");
  assert.match(authenticationGuide('standard', 'team', 'us-east-1').description, /If it is an IAM user/);
});
