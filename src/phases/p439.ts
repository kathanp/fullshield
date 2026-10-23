/**
 * Phase 439. CI templates.
 * Off unless FULLSHIELD_EXPERIMENTAL_CITPL=1.
 * Flag off: init does not copy the templates.
 * Templates run scan --fail-on high and store SARIF. They do not post comments.
 */
export const FLAG = 'FULLSHIELD_EXPERIMENTAL_CITPL';

const SCAN = 'npx fullshield scan --fail-on high';
const ARTIFACT = 'fullshield.sarif';
const PIN_NOTE = 'The user must pin any third-party image by digest.';

export function enabled(): boolean {
  return process.env[FLAG] === '1';
}

export const CI_TEMPLATES: Readonly<Record<string, string>> = {
  'templates/Jenkinsfile': `pipeline {
  agent any
  stages {
    stage('scan') {
      steps { sh '${SCAN} --sarif ${ARTIFACT}' }
    }
  }
  post { always { archiveArtifacts '${ARTIFACT}' } }
}
// ${PIN_NOTE}
`,
  'templates/circleci.yml': `version: 2.1
jobs:
  scan:
    steps:
      - run: ${SCAN} --sarif ${ARTIFACT}
      - store_artifacts:
          path: ${ARTIFACT}
# ${PIN_NOTE}
`,
  'templates/azure-pipelines.yml': `steps:
  - script: ${SCAN} --sarif ${ARTIFACT}
  - publish: ${ARTIFACT}
    artifact: fullshield
# ${PIN_NOTE}
`,
  'templates/bitbucket-pipelines.yml': `pipelines:
  default:
    - step:
        script:
          - ${SCAN} --sarif ${ARTIFACT}
        artifacts:
          - ${ARTIFACT}
# ${PIN_NOTE}
`,
};

const SECRET = /\bAKIA[0-9A-Z]{16}\b/;
const UNPINNED = /^\s*image:\s*(?!.*@sha256:)(\S+)\s*$/m;

export function assertTemplatePolicy(text: string): string[] {
  const errors: string[] = [];
  if (!text.includes('--fail-on') || !text.includes('high')) {
    errors.push('missing --fail-on high');
  }
  if (!text.includes(ARTIFACT)) {
    errors.push('missing artifact path');
  }
  if (text.includes('createComment')) {
    errors.push('comment API');
  }
  if (UNPINNED.test(text)) {
    errors.push('unpinned image');
  }
  if (SECRET.test(text)) {
    errors.push('secret-shaped token');
  }
  return errors;
}

export function templatesForInit(): Record<string, string> {
  if (!enabled()) {
    return {};
  }
  return { ...CI_TEMPLATES };
}
