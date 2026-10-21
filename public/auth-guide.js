export function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'"'"'`)}'`;
}

export function authenticationGuide(method, profile, region) {
  const selectedProfile = shellQuote(profile);
  switch (method) {
    case 'role-mfa':
      return {
        title: 'Authenticate this role here',
        description: 'Already signed in? Choose Connect to registry below. Otherwise, enter the current code from this role’s MFA device to open a temporary app session.',
        command: `aws sts get-caller-identity --profile ${selectedProfile} --region ${shellQuote(region)}`,
        next: 'If you use Terminal instead, return here and choose Retry connection after the command succeeds.',
      };
    case 'sso':
      return {
        title: 'Sign in with IAM Identity Center',
        description: 'The AWS CLI opens your organization’s sign-in page and completes MFA in the browser.',
        command: `aws sso login --profile ${selectedProfile}`,
        next: 'After sign-in succeeds, return here and choose Retry connection.',
      };
    case 'login':
      return {
        title: 'Sign in with your AWS profile',
        description: 'This profile uses the AWS CLI browser sign-in flow.',
        command: `aws login --profile ${selectedProfile}`,
        next: 'After sign-in succeeds, return here and choose Retry connection.',
      };
    case 'iam-user-mfa':
      return {
        title: 'Create an IAM user MFA session',
        description: 'The AWS CLI will request your one-time code and write temporary credentials to a separate session profile.',
        command: `aws configure mfa-login --profile ${selectedProfile}`,
        next: 'Choose a new destination profile at the CLI prompt. Then choose Refresh profiles here and connect using that new profile.',
      };
    default:
      return {
        title: 'MFA sign-in help',
        description: 'This profile has no MFA method declared in its CLI settings. If it is an IAM user whose API access requires MFA, create a temporary session profile with the command below.',
        command: `aws configure mfa-login --profile ${selectedProfile}`,
        next: 'The CLI prompts for the MFA device and a new destination profile. Refresh profiles here and select that session profile. For a role profile, configure mfa_serial first. For a custom credential provider, follow its own sign-in process.',
      };
  }
}
