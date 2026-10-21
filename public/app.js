import { authenticationGuide } from './auth-guide.js';

const $ = (id) => document.getElementById(id);
const tokenStorageKey = 'ecr-sentinel-launch-token';
const tokenPattern = /^[0-9a-f]{64}$/i;

function readLaunchToken() {
  const match = /^#token=([0-9a-f]{64})$/i.exec(location.hash);
  if (location.hash.startsWith('#token=')) {
    history.replaceState(null, '', `${location.pathname}${location.search}`);
    if (!match) {
      try { sessionStorage.removeItem(tokenStorageKey); } catch { /* No stored token to clear. */ }
      return '';
    }
  }
  if (match) {
    const token = match[1].toLowerCase();
    try { sessionStorage.setItem(tokenStorageKey, token); } catch { /* Current page still works. */ }
    return token;
  }
  try {
    const stored = sessionStorage.getItem(tokenStorageKey);
    if (stored && tokenPattern.test(stored)) return stored.toLowerCase();
    if (stored) sessionStorage.removeItem(tokenStorageKey);
  } catch { /* A private launch URL is required if storage is unavailable. */ }
  return '';
}

let apiToken = readLaunchToken();

const state = {
  profiles: [], profile: '', region: '', identity: null,
  repositories: [], repositoryToken: null, repository: null,
  images: [], imageToken: null, image: null,
  scanner: { checked: false, available: false, version: null, error: null, checkFailed: false },
  report: null, findings: [], reportLoading: false, reportError: null,
  visibleFindings: 100,
  scanJob: null, scanPollTimer: null, scanPollFailures: 0, pollError: null, cancelRequestedId: null,
  pendingSbomBundle: null, readingSbomFile: false,
  requestId: 0, repositoryRequestId: 0, findingRequestId: 0, connectionId: 0, activeDialog: null,
  drawerPriorFocus: null, modalPriorFocus: null,
  authMethod: 'standard', authRequestId: 0, roleMfaRequestId: 0,
};

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const scanPhases = {
  queued: 'Waiting for the local scanner',
  preflight: 'Checking AWS access and the selected image',
  'updating-db': 'Preparing vulnerability databases; the first scan may take several minutes',
  scanning: 'Trivy is analyzing the image',
  processing: 'Preparing the report',
};
const sbomScanPhases = {
  queued: 'Waiting for the local scanner',
  preflight: 'Checking the bundle and selected image identity',
  'updating-db': 'Preparing vulnerability databases; the first check may take several minutes',
  'scanning-sbom': 'Trivy is checking packages listed in the SBOM',
  processing: 'Preparing the SBOM findings report',
};
const MAX_SBOM_FILE_BYTES = 16 * 1024 * 1024;

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}

function replaceChildren(node, children) {
  node.replaceChildren(...children);
}

function formatDate(value, withTime = false) {
  if (!value) return '—';
  const date = new Date(timestampMs(value));
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    ...(withTime ? { hour: 'numeric', minute: '2-digit' } : {}),
  }).format(date);
}

function timestampMs(value) {
  return typeof value === 'number' ? value * 1000 : new Date(value || 0).getTime();
}

function formatSize(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function shortDigest(digest) {
  if (!digest) return 'Unknown digest';
  return digest.length > 24 ? `${digest.slice(0, 19)}…${digest.slice(-7)}` : digest;
}

function params(values) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null && value !== '') query.set(key, value);
  }
  return query.toString();
}

async function api(path, options = {}) {
  const { timeoutMs = 60000, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...fetchOptions,
      headers: {
        'X-ECR-Sentinel-Token': apiToken,
        ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...fetchOptions.headers,
      },
      signal: controller.signal,
      cache: 'no-store',
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.error?.message || `Request failed (${response.status}).`);
      error.code = data.error?.code || 'REQUEST_FAILED';
      if (error.code === 'INVALID_API_TOKEN') {
        apiToken = '';
        try { sessionStorage.removeItem(tokenStorageKey); } catch { /* The current session is already blocked. */ }
        showLaunchGate();
      }
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The request timed out. Check your VPN and AWS sign-in, then try again.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function toast(message, isError = false) {
  const wrapper = element('div', `toast${isError ? ' error' : ''}`);
  wrapper.append(icon(isError ? 'alert' : 'check'), element('span', '', message));
  const close = element('button', '', '');
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss notification');
  close.append(icon('close'));
  close.addEventListener('click', () => wrapper.remove());
  wrapper.append(close);
  $('toastStack').append(wrapper);
  setTimeout(() => wrapper.remove(), 6500);
}

function setLoading(button, loading, label) {
  button.disabled = loading;
  if (loading) button._originalNodes = [...button.childNodes].map((node) => node.cloneNode(true));
  if (loading) button.replaceChildren(document.createTextNode(label || 'Loading…'));
  else if (button._originalNodes) button.replaceChildren(...button._originalNodes.map((node) => node.cloneNode(true)));
}

function showSetup() {
  if (!apiToken) { showLaunchGate(); return; }
  $('lockTabButton').hidden = false;
  $('launchGate').hidden = true;
  $('setupCard').hidden = false;
  $('overviewGuidance').hidden = false;
  $('workspace').hidden = true;
  $('headingActions').hidden = true;
  $('pageTitle').textContent = 'Scan your ECR images locally';
  $('pageSubtitle').textContent = 'Connect an AWS profile, choose an image digest, then scan image layers or import a matching build-host SBOM.';
  $('topbarLocation').textContent = 'Overview';
  $('connectionAccount').textContent = 'Not connected';
  $('connectionMeta').textContent = 'Choose a profile to begin';
  $('connectionLight').classList.remove('connected');
  $('repoSearch').disabled = true;
  $('repoCount').textContent = '0';
  $('repoList').replaceChildren(element('p', 'sidebar-hint', 'Connect to load repositories.'));
  $('loadMoreRepos').hidden = true;
}

function showLaunchGate() {
  state.roleMfaRequestId += 1;
  $('roleMfaCode').value = '';
  state.connectionId += 1;
  state.repositoryRequestId += 1;
  state.requestId += 1;
  state.findingRequestId += 1;
  state.activeDialog = null;
  state.pendingSbomBundle = null;
  clearTimeout(state.scanPollTimer);
  state.scanPollTimer = null;
  $('confirmModal').hidden = true;
  $('confirmBackdrop').hidden = true;
  $('findingDrawer').hidden = true;
  $('drawerBackdrop').hidden = true;
  document.body.style.overflow = '';
  $('launchGate').hidden = false;
  $('lockTabButton').hidden = true;
  $('setupCard').hidden = true;
  $('scannerReadiness').hidden = true;
  $('overviewGuidance').hidden = true;
  $('workspace').hidden = true;
  $('headingActions').hidden = true;
  $('pageTitle').textContent = 'Open your private local session';
  $('pageSubtitle').textContent = 'ECR Sentinel needs the launch URL printed in the Terminal that started the app.';
  $('topbarLocation').textContent = 'Private session';
  $('connectionAccount').textContent = 'Session not open';
  $('connectionMeta').textContent = 'Open the Terminal launch URL';
  $('connectionLight').classList.remove('connected');
  $('repoSearch').disabled = true;
  $('repoList').replaceChildren(element('p', 'sidebar-hint', 'Open the private launch URL to load repositories.'));
}

function showWorkspace() {
  if (!apiToken) { showLaunchGate(); return; }
  $('roleMfaCode').value = '';
  $('lockTabButton').hidden = false;
  $('setupCard').hidden = true;
  $('overviewGuidance').hidden = true;
  $('workspace').hidden = false;
  $('headingActions').hidden = false;
  $('repoSearch').disabled = false;
  $('connectionLight').classList.add('connected');
  $('connectionAccount').textContent = state.identity?.account || 'Connected';
  $('connectionMeta').textContent = `${state.profile} · ${state.region}`;
  $('accountSummary').textContent = state.identity?.account || '—';
  $('regionSummary').textContent = state.region;
  $('scannerSummary').textContent = state.scanner.available
    ? `Trivy ${state.scanner.version || 'ready'}` : 'Trivy unavailable';
  $('repoSummary').textContent = String(state.repositories.length);
  showRepositoryOverview();
}

async function loadScannerStatus() {
  const button = $('checkScannerButton');
  setLoading(button, true, 'Checking…');
  $('scannerStateTitle').textContent = 'Checking local scanner…';
  $('scannerStateDescription').textContent = 'Looking for Trivy on this Mac.';
  try {
    const result = await api('/api/scanner/status');
    state.scanner = {
      checked: true,
      available: result.available === true,
      version: result.version || null,
      error: result.error?.message || null,
      checkFailed: false,
    };
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    state.scanner = { checked: true, available: false, version: null, error: error.message, checkFailed: true };
  } finally {
    setLoading(button, false);
  }
  renderScannerStatus();
  if (!$('findingDrawer').hidden) renderScanStatus();
}

function renderScannerStatus() {
  const ready = state.scanner.available;
  $('scannerReadiness').classList.toggle('scanner-unavailable', state.scanner.checked && !ready);
  $('scannerStateTitle').textContent = ready
    ? `Trivy ${state.scanner.version || 'is ready'} on this Mac`
    : state.scanner.checkFailed ? 'Could not check Trivy' : 'Trivy is needed for local scanning';
  $('scannerStateDescription').textContent = ready
    ? 'Trivy scans ECR images when pull access is available, or checks an imported SBOM without downloading image layers. Database updates may need internet access.'
    : (state.scanner.error || (state.scanner.checkFailed
      ? 'The local app could not verify the scanner. Check again.'
      : 'Install Trivy, then check again. Registry browsing remains available.'));
  $('scannerInstall').hidden = ready || !state.scanner.checked || state.scanner.checkFailed;
  $('scannerSummary').textContent = ready ? `Trivy ${state.scanner.version || 'ready'}`
    : state.scanner.checkFailed ? 'Check unavailable' : 'Trivy unavailable';
}

function setAuthHelpOpen(open) {
  if (!open) {
    state.roleMfaRequestId += 1;
    $('roleMfaCode').value = '';
    $('roleMfaError').hidden = true;
  }
  $('authHelp').hidden = !open;
  $('authHelpToggle').setAttribute('aria-expanded', String(open));
}

function renderAuthHelp() {
  const profile = $('profileSelect').value;
  const guide = authenticationGuide(state.authMethod, profile, $('regionInput').value.trim());
  const roleMfa = state.authMethod === 'role-mfa';
  $('authHelpTitle').textContent = guide.title;
  $('authHelpDescription').textContent = guide.description;
  $('roleMfaFlow').hidden = !roleMfa;
  $('authTerminalSummary').textContent = roleMfa ? 'Use Terminal instead' : 'Sign in using Terminal';
  $('authPrivacy').textContent = roleMfa
    ? 'Your code goes to this local app and AWS for sign-in. Sentinel does not save it in browser storage or reports.'
    : 'Enter your MFA code only in the AWS CLI or your organization’s sign-in page. Sentinel does not receive it.';
  $('authCommand').textContent = profile ? guide.command : 'Select an AWS profile first.';
  $('authNextStep').textContent = guide.next;
  $('copyAuthCommand').disabled = !profile;
  $('retryConnectionButton').disabled = !profile;
  $('refreshProfilesButton').hidden = !['standard', 'iam-user-mfa'].includes(state.authMethod);
}

async function loadAuthMethod(profile) {
  const requestId = ++state.authRequestId;
  state.roleMfaRequestId += 1;
  $('roleMfaCode').value = '';
  $('roleMfaError').hidden = true;
  state.authMethod = 'standard';
  renderAuthHelp();
  if (!profile) {
    setAuthHelpOpen(false);
    return;
  }
  try {
    const result = await api(`/api/auth-method?${params({ profile })}`);
    if (requestId !== state.authRequestId || $('profileSelect').value !== profile) return;
    state.authMethod = result.authMethod || 'standard';
    renderAuthHelp();
    $('authTerminalDetails').open = state.authMethod !== 'role-mfa';
    setAuthHelpOpen(state.authMethod !== 'standard');
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    if (requestId !== state.authRequestId) return;
    $('authHelpDescription').textContent = `Could not inspect this profile's sign-in settings. ${error.message}`;
  }
}

async function loadProfiles({ refresh = false } = {}) {
  const select = $('profileSelect');
  const previousSelection = select.value;
  try {
    const result = await api(`/api/profiles${refresh ? '?refresh=1' : ''}`);
    state.profiles = Array.isArray(result.profiles) ? result.profiles : [];
    select.replaceChildren();
    if (!state.profiles.length) {
      select.append(element('option', '', 'No AWS profiles found'));
      select.disabled = true;
      $('profileHelp').textContent = 'Configure a profile with aws configure or aws sso login, then reload this page.';
      $('connectButton').disabled = true;
      return;
    }
    select.append(element('option', '', 'Select a profile'));
    select.firstChild.value = '';
    for (const name of state.profiles) {
      const option = element('option', '', name);
      option.value = name;
      select.append(option);
    }
    let saved = null;
    try { saved = JSON.parse(sessionStorage.getItem('ecr-sentinel-connection') || 'null'); }
    catch { sessionStorage.removeItem('ecr-sentinel-connection'); }
    const preferred = state.profiles.includes(previousSelection) ? previousSelection
      : state.profiles.includes(saved?.profile) ? saved.profile : '';
    if (preferred) select.value = preferred;
    if (!refresh && saved && preferred === saved.profile) $('regionInput').value = saved.region || 'us-east-1';
    loadAuthMethod(preferred);
    if (!refresh && saved && preferred === saved.profile) connect(saved.profile, saved.region || 'us-east-1', true);
    if (refresh) toast('AWS profiles refreshed. Select a new MFA session profile if you created one.');
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    if (refresh) { toast(error.message, true); return; }
    select.replaceChildren(element('option', '', 'AWS CLI unavailable'));
    select.disabled = true;
    $('profileHelp').textContent = error.message;
    $('connectButton').disabled = true;
    toast(error.message, true);
  }
}

async function connect(profile, region, silent = false) {
  const button = $('connectButton');
  const errorLine = $('connectionError');
  errorLine.hidden = true;
  if (!state.profiles.includes(profile)) {
    errorLine.textContent = 'Choose a configured AWS profile.';
    errorLine.hidden = false;
    return;
  }
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) {
    errorLine.textContent = 'Enter a valid AWS Region, such as us-east-1.';
    errorLine.hidden = false;
    return;
  }
  setLoading(button, true, 'Connecting…');
  const connectionId = ++state.connectionId;
  state.repositoryRequestId += 1;
  state.requestId += 1;
  state.findingRequestId += 1;
  try {
    const identity = await api(`/api/identity?${params({ profile, region })}`);
    if (connectionId !== state.connectionId) return;
    state.profile = profile;
    state.region = region;
    state.identity = identity;
    state.repositories = [];
    state.repositoryToken = null;
    state.repository = null;
    state.images = [];
    state.image = null;
    sessionStorage.setItem('ecr-sentinel-connection', JSON.stringify({ profile, region }));
    showWorkspace();
    await loadRepositories();
    if (connectionId !== state.connectionId) return;
    if (!silent) toast(`Connected to AWS account ${identity.account} in ${region}.`);
  } catch (error) {
    if (connectionId !== state.connectionId) return;
    errorLine.textContent = error.message;
    errorLine.hidden = false;
    if (['AWS_MFA_REQUIRED', 'AWS_SESSION_EXPIRED'].includes(error.code) ||
      (state.authMethod === 'role-mfa' && ['AWS_TIMEOUT', 'AWS_ACCESS_DENIED', 'AWS_REQUEST_FAILED'].includes(error.code))) {
      setAuthHelpOpen(true);
    }
    if (silent) toast(error.message, true);
    sessionStorage.removeItem('ecr-sentinel-connection');
    showSetup();
  } finally {
    setLoading(button, false);
  }
}

async function authenticateRoleMfa() {
  const profile = $('profileSelect').value;
  const region = $('regionInput').value.trim();
  const codeInput = $('roleMfaCode');
  const errorLine = $('roleMfaError');
  const button = $('submitRoleMfaButton');
  const code = codeInput.value.trim();
  codeInput.value = '';
  errorLine.hidden = true;
  if (state.authMethod !== 'role-mfa' || !state.profiles.includes(profile)) {
    errorLine.textContent = 'Select a configured role profile with an MFA device.';
    errorLine.hidden = false;
    return;
  }
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) {
    errorLine.textContent = 'Enter a valid AWS Region, such as us-east-1.';
    errorLine.hidden = false;
    $('regionInput').focus();
    return;
  }
  if (!/^[0-9]{6}$/.test(code)) {
    errorLine.textContent = 'Enter the current 6-digit code from your MFA device.';
    errorLine.hidden = false;
    codeInput.focus();
    return;
  }
  const requestId = ++state.roleMfaRequestId;
  setLoading(button, true, 'Verifying…');
  codeInput.disabled = true;
  $('profileSelect').disabled = true;
  $('regionInput').disabled = true;
  $('connectButton').disabled = true;
  $('authHelpToggle').disabled = true;
  try {
    await api('/api/auth/mfa', {
      method: 'POST',
      body: JSON.stringify({ profile, region, code }),
      timeoutMs: 90_000,
    });
    if (requestId !== state.roleMfaRequestId || !apiToken) return;
    await connect(profile, region);
  } catch (error) {
    if (requestId !== state.roleMfaRequestId || error.code === 'INVALID_API_TOKEN') return;
    errorLine.textContent = error.message;
    errorLine.hidden = false;
    if (error.code === 'AWS_MFA_UNSUPPORTED') $('authTerminalDetails').open = true;
    codeInput.focus();
  } finally {
    setLoading(button, false);
    codeInput.disabled = false;
    $('profileSelect').disabled = false;
    $('regionInput').disabled = false;
    $('connectButton').disabled = false;
    $('authHelpToggle').disabled = false;
  }
}

function showRepositoryOverview() {
  state.repository = null;
  $('repoOverview').hidden = false;
  $('imagesView').hidden = true;
  $('pageTitle').textContent = 'Registry overview';
  $('pageSubtitle').textContent = `Explore private ECR repositories in ${state.region}, then scan image layers or check a matching build-host SBOM.`;
  $('topbarLocation').textContent = 'Overview';
  renderRepositoryNavigation();
  renderRepositoryGrid();
}

async function loadRepositories(append = false) {
  const button = $('loadMoreRepos');
  const requestId = ++state.repositoryRequestId;
  const profile = state.profile;
  const region = state.region;
  if (append) setLoading(button, true, 'Loading…');
  else {
    state.repositories = [];
    state.repositoryToken = null;
    $('repoSummary').textContent = '0';
    $('repoList').replaceChildren(element('p', 'sidebar-hint', 'Loading repositories…'));
    $('repositoryGrid').replaceChildren();
    $('repositoriesEmpty').hidden = true;
  }
  try {
    const result = await api(`/api/repositories?${params({
      profile, region,
      nextToken: append ? state.repositoryToken : undefined,
    })}`);
    if (requestId !== state.repositoryRequestId || profile !== state.profile || region !== state.region) return;
    const incoming = Array.isArray(result.items) ? result.items : [];
    state.repositories = append
      ? [...state.repositories, ...incoming.filter((repo) => !state.repositories.some((existing) => existing.name === repo.name))]
      : incoming;
    state.repositoryToken = result.nextToken || null;
    $('repoSummary').textContent = String(state.repositories.length);
    renderRepositoryNavigation();
    renderRepositoryGrid();
  } catch (error) {
    if (requestId !== state.repositoryRequestId || profile !== state.profile || region !== state.region) return;
    if (!append) {
      $('repoList').replaceChildren(element('p', 'sidebar-hint', 'Unable to load repositories. Use Refresh to retry.'));
      $('repositoriesEmpty').hidden = false;
      $('repositoriesEmpty').querySelector('h3').textContent = 'Could not load repositories';
      $('repositoriesEmpty').querySelector('p').textContent = error.message;
    }
    toast(error.message, true);
  } finally {
    if (append && requestId === state.repositoryRequestId) setLoading(button, false);
  }
}

function filteredRepositories() {
  const query = $('repoSearch').value.trim().toLowerCase();
  return state.repositories.filter((repo) => repo.name.toLowerCase().includes(query));
}

function renderRepositoryNavigation() {
  const list = $('repoList');
  const repos = filteredRepositories();
  const items = repos.map((repo) => {
    const button = element('button', state.repository?.name === repo.name ? 'active' : '');
    button.type = 'button';
    button.title = repo.name;
    button.append(icon('box'), element('span', '', repo.name), icon('chevron'));
    button.addEventListener('click', () => selectRepository(repo));
    return button;
  });
  if (!items.length) {
    const text = state.repositories.length ? 'No repositories match your search.' : 'No repositories loaded.';
    items.push(element('p', 'sidebar-hint', text));
  }
  replaceChildren(list, items);
  $('repoCount').textContent = String(state.repositories.length);
  $('loadMoreRepos').hidden = !state.repositoryToken;
}

function renderRepositoryGrid() {
  const repos = filteredRepositories();
  const grid = $('repositoryGrid');
  const tiles = repos.slice(0, 9).map((repo) => {
    const button = element('button', 'repository-tile');
    button.type = 'button';
    button.title = `Open ${repo.name}`;
    const top = element('div', 'repository-tile-top');
    top.append(icon('box'), icon('arrow'));
    button.append(top, element('strong', '', repo.name), element('span', '', 'Private ECR · local scans'));
    button.addEventListener('click', () => selectRepository(repo));
    return button;
  });
  replaceChildren(grid, tiles);
  $('repositoriesEmpty').hidden = state.repositories.length > 0 || Boolean(state.repositoryToken);
  if (state.repositories.length) {
    $('repositoriesEmpty').querySelector('h3').textContent = 'No matching repositories';
    $('repositoriesEmpty').querySelector('p').textContent = 'Try a different search term in the sidebar.';
    $('repositoriesEmpty').hidden = repos.length > 0;
  }
}

function selectRepository(repo) {
  state.repository = repo;
  state.images = [];
  state.imageToken = null;
  $('repoOverview').hidden = true;
  $('imagesView').hidden = false;
  $('pageTitle').textContent = repo.name;
  $('pageSubtitle').textContent = 'Browse image digests, scan image layers or import a matching SBOM, and inspect Trivy findings.';
  $('topbarLocation').textContent = repo.name;
  $('imagesTitle').textContent = repo.name;
  $('imagesSubtitle').textContent = repo.uri || 'Private ECR repository';
  $('repoScanPill').textContent = 'Trivy · image or SBOM';
  $('imageSearch').value = '';
  $('imageSort').value = 'newest';
  renderRepositoryNavigation();
  closeSidebar();
  loadImages();
}

async function loadImages(append = false) {
  const repo = state.repository;
  if (!repo) return;
  const requestId = ++state.requestId;
  const button = $('loadMoreImages');
  if (append) setLoading(button, true, 'Loading…');
  else {
    state.images = [];
    state.imageToken = null;
    $('imageRows').replaceChildren(...Array.from({ length: 4 }, () => {
      const row = element('tr');
      for (let i = 0; i < 5; i += 1) {
        const td = element('td');
        const skeleton = element('span', 'skeleton');
        skeleton.style.width = i === 0 ? '130px' : '80px';
        skeleton.style.height = '12px';
        td.append(skeleton);
        row.append(td);
      }
      return row;
    }));
    $('imagesEmpty').hidden = true;
  }
  try {
    const result = await api(`/api/images?${params({
      profile: state.profile, region: state.region, repository: repo.name,
      nextToken: append ? state.imageToken : undefined,
    })}`);
    if (requestId !== state.requestId || state.repository?.name !== repo.name) return;
    const incoming = Array.isArray(result.items) ? result.items : [];
    state.images = append
      ? [...state.images, ...incoming.filter((image) => !state.images.some((existing) => existing.digest === image.digest))]
      : incoming;
    state.imageToken = result.nextToken || null;
    renderImages();
  } catch (error) {
    if (requestId !== state.requestId) return;
    if (!append) {
      $('imageRows').replaceChildren();
      $('imagesEmpty').hidden = false;
      $('imagesEmptyTitle').textContent = 'Could not load images';
      $('imagesEmptyText').textContent = error.message;
    }
    toast(error.message, true);
  } finally {
    if (append) setLoading(button, false);
  }
}

function renderImages() {
  const query = $('imageSearch').value.trim().toLowerCase();
  const sort = $('imageSort').value;
  const images = state.images.filter((image) =>
    image.digest?.toLowerCase().includes(query) ||
    (image.tags || []).some((tag) => tag.toLowerCase().includes(query)));
  images.sort((a, b) => {
    if (sort === 'tag') return (a.tags?.[0] || '').localeCompare(b.tags?.[0] || '');
    const dateA = timestampMs(a.pushedAt);
    const dateB = timestampMs(b.pushedAt);
    return sort === 'oldest' ? dateA - dateB : dateB - dateA;
  });
  const rows = images.map((image) => {
    const row = element('tr');
    const identity = element('td', 'image-title-cell');
    identity.append(element('strong', '', image.tags?.[0] || 'Untagged image'));
    identity.append(element('span', '', image.status === 'ARCHIVED'
      ? 'Archived image'
      : image.tags?.length > 1
        ? `+${image.tags.length - 1} other tag${image.tags.length > 2 ? 's' : ''}`
        : (image.artifactMediaType || 'Container image')));
    const digestCell = element('td');
    const digest = element('span', 'digest-text', shortDigest(image.digest));
    digest.title = image.digest || '';
    digestCell.append(digest);
    const actionCell = element('td');
    const action = element('button', 'row-action', 'Review & scan');
    action.type = 'button';
    action.append(icon('chevron'));
    action.addEventListener('click', () => openImage(image));
    actionCell.append(action);
    row.append(identity, digestCell, element('td', '', formatDate(image.pushedAt)), element('td', '', formatSize(image.sizeBytes)), actionCell);
    return row;
  });
  replaceChildren($('imageRows'), rows);
  $('imageCountLabel').textContent = `${state.images.length} loaded`;
  $('imagesFooter').textContent = state.imageToken ? 'More images are available from AWS' : `${state.images.length} image${state.images.length === 1 ? '' : 's'} loaded`;
  $('loadMoreImages').hidden = !state.imageToken;
  $('imagesEmpty').hidden = images.length > 0;
  if (!images.length) {
    $('imagesEmptyTitle').textContent = state.images.length ? 'No matching images' : 'No images yet';
    $('imagesEmptyText').textContent = state.images.length ? 'Try a different tag or digest.' : 'This repository has no images. Push an image to ECR, then refresh.';
  }
}

function openImage(image) {
  clearTimeout(state.scanPollTimer);
  state.scanPollTimer = null;
  state.image = image;
  state.report = null;
  state.findings = [];
  state.visibleFindings = 100;
  state.reportError = null;
  state.scanJob = null;
  state.pollError = null;
  state.cancelRequestedId = null;
  state.scanPollFailures = 0;
  state.pendingSbomBundle = null;
  $('sbomImportError').hidden = true;
  state.drawerPriorFocus = document.activeElement;
  $('drawerTitle').textContent = image.tags?.[0] || 'Untagged image';
  $('drawerProfile').textContent = `AWS profile: ${state.profile} · ${state.region}`;
  $('drawerDigest').textContent = image.digest || 'Unknown digest';
  $('drawerTags').replaceChildren(...(image.tags?.length
    ? image.tags.map((tag) => element('span', 'tag-chip', tag))
    : [element('span', 'tag-chip', 'Untagged')]));
  $('findingSearch').value = '';
  $('severityFilter').value = 'ALL';
  $('platformSelect').value = 'linux/amd64';
  $('findingDrawer').hidden = false;
  $('drawerBackdrop').hidden = false;
  document.body.style.overflow = 'hidden';
  $('closeDrawer').focus();
  renderScanStatus();
  renderSeverity();
  $('findingList').replaceChildren();
  $('findingsEmpty').hidden = false;
  $('findingsCountLabel').textContent = 'Checking for a previous local report…';
  $('exportButton').disabled = true;
  loadLatestReport();
}

function closeDrawer() {
  clearTimeout(state.scanPollTimer);
  state.scanPollTimer = null;
  state.findingRequestId += 1;
  state.pendingSbomBundle = null;
  $('findingDrawer').hidden = true;
  $('drawerBackdrop').hidden = true;
  if ($('confirmModal').hidden) document.body.style.overflow = '';
  if (state.drawerPriorFocus?.isConnected) state.drawerPriorFocus.focus();
}

function currentScanKey() {
  return [state.profile, state.region, state.repository?.name, state.image?.digest,
    $('platformSelect').value].join('\n');
}

async function loadLatestReport() {
  if (!state.image || !state.repository) return;
  clearTimeout(state.scanPollTimer);
  state.scanPollTimer = null;
  const requestId = ++state.findingRequestId;
  const key = currentScanKey();
  state.reportLoading = true;
  state.reportError = null;
  state.pollError = null;
  renderScanStatus();
  try {
    const result = await api(`/api/scans/latest?${params({
      profile: state.profile, region: state.region, repository: state.repository.name,
      digest: state.image.digest, platform: $('platformSelect').value,
    })}`);
    if (requestId !== state.findingRequestId || key !== currentScanKey() || $('findingDrawer').hidden) return;
    if (state.report?.scannedAt !== result.report?.scannedAt) state.visibleFindings = 100;
    state.report = result.report || null;
    state.findings = Array.isArray(state.report?.findings) ? state.report.findings : [];
    state.scanJob = result.job || null;
    state.scanPollFailures = 0;
    renderScanStatus();
    renderSeverity();
    renderFindings();
    if (state.scanJob && ['PENDING', 'IN_PROGRESS'].includes(state.scanJob.status)) scheduleScanPoll();
  } catch (error) {
    if (requestId !== state.findingRequestId || key !== currentScanKey() || $('findingDrawer').hidden) return;
    state.reportError = error.message;
    renderScanStatus();
    renderFindings();
  } finally {
    if (requestId === state.findingRequestId && key === currentScanKey()) {
      state.reportLoading = false;
      renderScanStatus();
      renderFindings();
    }
  }
}

function renderScanStatus() {
  const job = state.scanJob;
  const report = state.report;
  const sbomJob = job?.mode === 'sbom';
  const sbomReport = report?.scanMode === 'sbom';
  const active = job && ['PENDING', 'IN_PROGRESS'].includes(job.status);
  let title = 'No local report yet';
  let description = 'Scan the image with Trivy, or import a matching SBOM bundle from an authorized build host.';
  let tone = 'warn';
  if (state.reportLoading) {
    title = 'Checking local report history';
    description = 'Looking for an earlier image or SBOM report from this app session.';
  } else if (active) {
    const stopping = state.cancelRequestedId === job.id;
    title = stopping ? 'Stopping local check' : job.status === 'PENDING' ? 'Check queued'
      : sbomJob ? 'SBOM check running' : 'Trivy image scan running';
    description = state.pollError
      ? `Could not refresh progress: ${state.pollError} Use Refresh to retry.`
      : `${stopping ? 'Waiting for the Trivy process to stop' : (sbomJob ? sbomScanPhases : scanPhases)[job.phase] || (sbomJob ? 'Trivy is checking this SBOM' : 'Trivy is working on this image')}.${report ? ' Showing the previous completed report below.' : ''}`;
  } else if (job?.status === 'FAILED' || job?.status === 'CANCELED') {
    title = job.status === 'FAILED' ? (sbomJob ? 'SBOM check failed' : 'Image scan failed') : 'Check canceled';
    description = `${job.error?.message || 'The local check did not complete.'}${report ? ' The previous completed report is shown below.' : ' Retry when ready.'}`;
    tone = job.status === 'FAILED' ? 'error' : 'warn';
  } else if (state.reportError) {
    title = 'Could not load local scan history';
    description = `${state.reportError}${report ? ' The previous report is still shown below.' : ' Use Refresh to retry.'}`;
    tone = 'error';
  } else if (job?.status === 'COMPLETE' && !report) {
    title = 'Earlier report expired from this session';
    description = 'This image was scanned, but its detailed report is no longer in local app memory. Rescan to view findings.';
  } else if (report) {
    title = sbomReport ? 'SBOM vulnerability check complete' : 'Local Trivy image scan complete';
    description = report.coverage?.noPackagesDetected
      ? `Trivy detected no package targets in ${sbomReport ? 'this SBOM' : 'this image'}. This report cannot establish whether the image has known package vulnerabilities.`
      : report.coverage?.limitedCoverage
        ? `Trivy checked the package types shown below. Coverage is limited to ${sbomReport ? 'packages recorded in the SBOM' : 'targets it detected in the image'}.`
        : sbomReport
          ? 'Trivy checked the packages recorded in the imported SBOM. The bundle’s image association and producer are unverified claims.'
          : 'These findings came from Trivy on this Mac for the selected digest and platform.';
    tone = report.coverage?.noPackagesDetected ? 'warn' : 'good';
  } else if (!state.scanner.available && state.scanner.checked) {
    title = state.scanner.checkFailed ? 'Scanner check unavailable' : 'Trivy unavailable';
    description = state.scanner.checkFailed
      ? 'Use Check again above to verify the local scanner.'
      : 'Install Trivy, then use Check again above before starting a scan.';
    tone = 'error';
  }
  const card = $('scanStatusCard');
  card.className = `scan-status-card status-${tone}`;
  card.querySelector('.status-icon').replaceChildren(icon(tone === 'good' ? 'check' : tone === 'error' ? 'alert' : 'info'));
  $('scanStatusTitle').textContent = title;
  $('scanStatusDescription').textContent = description;
  $('scanSwitchProfileButton').hidden = job?.status !== 'FAILED' || job.error?.code !== 'ECR_PULL_DENIED';
  $('scanTimestamp').textContent = active && job.startedAt
    ? `Started ${formatDate(job.startedAt, true)}`
    : report?.scannedAt ? `Completed ${formatDate(report.scannedAt, true)}`
      : job?.completedAt ? `Completed ${formatDate(job.completedAt, true)}` : '';

  const provenance = $('scanProvenance');
  provenance.hidden = !report;
  $('reportCoverageNote').hidden = !report?.coverage?.note;
  $('reportRetention').hidden = !report;
  $('reportSbomProducerRow').hidden = !sbomReport;
  $('reportSbomHashRow').hidden = !sbomReport;
  $('reportSbomAssociation').hidden = !sbomReport;
  if (report) {
    $('reportScanner').textContent = `${report.source || 'Trivy'} ${report.scannerVersion || ''}`.trim();
    $('reportDbDate').textContent = formatDate(report.dbUpdatedAt, true);
    $('reportImageLabel').textContent = sbomReport ? 'Claimed image' : 'Image';
    $('reportImage').textContent = `${shortDigest(report.digest || state.image?.digest)} · ${report.platform || $('platformSelect').value}`;
    $('reportImage').title = report.digest || state.image?.digest || '';
    if (sbomReport) {
      const producer = report.provenance?.producer;
      const producerName = typeof producer === 'string' ? producer : producer?.name;
      $('reportSbomProducer').textContent = `${producerName || 'Unspecified'} · ${formatDate(report.provenance?.generatedAt, true)} (bundle claim)`;
      $('reportSbomHash').textContent = report.provenance?.sbomSha256 || 'Unavailable';
    }
    const packageTypes = Array.isArray(report.coverage?.packageTypes) ? report.coverage.packageTypes : [];
    $('reportCoverage').textContent = report.coverage?.noPackagesDetected
      ? 'No package targets detected'
      : packageTypes.length ? `${packageTypes.join(' + ')} package targets${report.coverage?.limitedCoverage ? ' · limited' : ''}`
        : 'Package targets reported by Trivy';
    $('reportCoverageNote').textContent = report.coverage?.note || '';
  }

  const button = $('startScanButton');
  button.replaceChildren(icon('scan'), document.createTextNode('Scan image with Trivy'));
  button.disabled = !state.scanner.available || !state.image || state.image.status === 'ARCHIVED' || Boolean(active) || state.reportLoading || state.readingSbomFile || Boolean(state.activeDialog);
  $('importSbomButton').disabled = !state.scanner.available || !state.image || !state.repository || Boolean(active) || state.reportLoading || state.readingSbomFile || Boolean(state.activeDialog);
  $('cancelRunningScanButton').hidden = !active;
  $('cancelRunningScanButton').disabled = !job?.id || state.cancelRequestedId === job.id;
  $('drawerScanHint').textContent = state.image?.status === 'ARCHIVED'
    ? 'Image layers are archived. A matching SBOM bundle can still be checked locally.'
    : active ? 'This check continues on your Mac if you close the report.'
      : !state.scanner.available ? (state.scanner.checkFailed
        ? 'Check the local scanner again to enable both scan paths.' : 'Install Trivy and check again to enable both scan paths.')
        : 'Import a matching SBOM bundle to check packages without downloading image layers.';
}

function renderSeverity() {
  const counts = state.report?.counts || state.report?.summary?.counts || {};
  const cards = severityOrder.map((severity) => {
    const card = element('div', `severity-card ${severity.toLowerCase()}`);
    const count = counts[severity];
    card.append(element('strong', '', Number.isFinite(count) ? count : '—'),
      element('span', '', severity.toLowerCase()));
    return card;
  });
  replaceChildren($('severityGrid'), cards);
  $('severityGrid').hidden = !state.report || Boolean(state.report.coverage?.noPackagesDetected);
}

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch { return null; }
}

function renderFindings() {
  const query = $('findingSearch').value.trim().toLowerCase();
  const severity = $('severityFilter').value;
  const findings = state.findings.filter((finding) => {
    const matchSeverity = severity === 'ALL' || finding.severity === severity;
    const text = [finding.id, finding.title, finding.packageName, finding.target, finding.type,
      ...(finding.packages || []).map((item) => item.name)].filter(Boolean).join(' ').toLowerCase();
    return matchSeverity && text.includes(query);
  }).sort((a, b) => {
    const severityDelta = severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    return severityDelta || (b.score || 0) - (a.score || 0) || (a.id || '').localeCompare(b.id || '');
  });

  const visible = findings.slice(0, state.visibleFindings);
  const cards = visible.map((finding) => {
    const card = element('article', 'finding-card');
    const head = element('div', 'finding-card-head');
    const title = element('div', 'finding-card-title');
    title.append(element('span', 'finding-id', finding.id || 'Unidentified finding'),
      element('span', `severity-pill ${(finding.severity || '').toLowerCase()}`, finding.severity || 'UNKNOWN'));
    head.append(title);
    const url = safeExternalUrl(finding.uri);
    if (url) {
      const link = element('a', '', 'Advisory');
      link.href = url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.append(icon('external'));
      head.append(link);
    }
    card.append(head, element('h4', '', finding.title || finding.id || 'Vulnerability finding'));
    if (finding.description) card.append(element('p', '', finding.description));
    const meta = element('div', 'finding-meta');
    if (finding.packageName) {
      const pkg = element('span');
      pkg.append(element('strong', '', finding.packageName), document.createTextNode(finding.installedVersion ? ` ${finding.installedVersion}` : ''));
      meta.append(pkg);
    }
    if (finding.fixedVersion) {
      const fix = element('span');
      fix.append(document.createTextNode('Fix: '), element('strong', '', finding.fixedVersion));
      meta.append(fix);
    } else {
      meta.append(element('span', '', 'No fix reported'));
    }
    if (Number.isFinite(finding.score)) meta.append(element('span', '', `CVSS ${finding.score.toFixed(1)}`));
    if (finding.target) meta.append(element('span', '', `Target: ${finding.target}`));
    if (finding.type) meta.append(element('span', '', finding.type));
    if (finding.packages?.length > 1) meta.append(element('span', '', `+${finding.packages.length - 1} affected packages`));
    if (meta.childNodes.length) card.append(meta);
    const hasMore = (finding.description?.length || 0) > 160 || finding.descriptionTruncated || (finding.packages?.length || 0) > 1;
    if (hasMore) {
      const details = element('details', 'finding-details');
      details.append(element('summary', '', 'Show available details'));
      if (finding.description) details.append(element('p', 'full-description', finding.description));
      if (finding.descriptionTruncated) details.append(element('p', 'description-limit-note', 'Description shortened in this local report. Open the advisory for more context.'));
      if (finding.packages?.length > 1) {
        details.append(element('strong', 'packages-heading', 'Affected packages'));
        const packageList = element('ul', 'package-list');
        for (const pkg of finding.packages) {
          packageList.append(element('li', '', `${pkg.name || 'Unknown package'} ${pkg.installedVersion || ''} → ${pkg.fixedVersion || 'No fixed version reported'}`));
        }
        details.append(packageList);
      }
      card.append(details);
    }
    return card;
  });
  replaceChildren($('findingList'), cards);
  $('findingsCountLabel').textContent = state.report
    ? `${visible.length} shown · ${findings.length} matching of ${state.findings.length} in this report`
    : state.reportLoading ? 'Checking for a previous local report…' : 'No completed report';
  $('loadMoreFindings').hidden = visible.length >= findings.length;
  $('exportButton').disabled = !state.report;
  $('findingsEmpty').hidden = findings.length > 0;
  if (!findings.length) {
    const sbomReport = state.report?.scanMode === 'sbom';
    if (state.report && (query || severity !== 'ALL')) {
      $('findingsEmptyTitle').textContent = 'No matching findings';
      $('findingsEmptyText').textContent = 'Try a different advisory, package, target, or severity filter.';
    } else if (state.report?.coverage?.noPackagesDetected) {
      $('findingsEmptyTitle').textContent = 'No package targets detected';
      $('findingsEmptyText').textContent = sbomReport
        ? 'The imported SBOM contains no package targets Trivy could check. Zero findings do not establish image vulnerability coverage.'
        : 'Trivy completed but found no OS or library package targets for this platform. A zero-finding result here does not establish vulnerability coverage.';
    } else if (state.report) {
      $('findingsEmptyTitle').textContent = 'No known vulnerabilities found';
      $('findingsEmptyText').textContent = sbomReport
        ? 'Trivy found no known vulnerabilities in packages recorded in this SBOM using the recorded database. Other packages may be absent, and the image association is unverified.'
        : 'Trivy found no known package vulnerabilities for this digest and platform using the recorded database. This is not a guarantee that the image is vulnerability free.';
    } else if (state.reportLoading) {
      $('findingsEmptyTitle').textContent = 'Checking local history';
      $('findingsEmptyText').textContent = 'Looking for an earlier scan of this digest and platform.';
    } else if (state.scanJob && ['PENDING', 'IN_PROGRESS'].includes(state.scanJob.status)) {
      $('findingsEmptyTitle').textContent = state.scanJob.mode === 'sbom' ? 'SBOM check in progress' : 'Image scan in progress';
      $('findingsEmptyText').textContent = 'Findings will appear when Trivy completes.';
    } else if (state.reportError) {
      $('findingsEmptyTitle').textContent = 'Could not load scan history';
      $('findingsEmptyText').textContent = state.reportError;
    } else if (state.scanJob?.status === 'FAILED') {
      $('findingsEmptyTitle').textContent = 'Scan did not complete';
      $('findingsEmptyText').textContent = state.scanJob.error?.message || 'Review the scan error above, then try again.';
    } else if (state.scanJob?.status === 'CANCELED') {
      $('findingsEmptyTitle').textContent = 'Scan canceled';
      $('findingsEmptyText').textContent = 'Start a new scan when you are ready.';
    } else if (state.scanJob?.status === 'COMPLETE') {
      $('findingsEmptyTitle').textContent = 'Earlier report expired';
      $('findingsEmptyText').textContent = 'The completed report is no longer in this app session. Rescan this digest and platform to view findings.';
    } else {
      $('findingsEmptyTitle').textContent = 'No local report yet';
      $('findingsEmptyText').textContent = 'Scan image layers with Trivy, or import a matching SBOM bundle to check its recorded packages.';
    }
  }
}

function scheduleScanPoll() {
  clearTimeout(state.scanPollTimer);
  if (!state.scanJob || !['PENDING', 'IN_PROGRESS'].includes(state.scanJob.status) || $('findingDrawer').hidden) return;
  state.scanPollTimer = setTimeout(() => {
    pollScanJob();
  }, state.scanPollFailures ? 5000 : 2500);
}

async function pollScanJob() {
  const jobId = state.scanJob?.id;
  if (!jobId || $('findingDrawer').hidden) return;
  const key = currentScanKey();
  const requestId = state.findingRequestId;
  try {
    const job = await api(`/api/scans/${encodeURIComponent(jobId)}`);
    if (requestId !== state.findingRequestId || key !== currentScanKey() || $('findingDrawer').hidden) return;
    state.scanJob = job;
    if (!['PENDING', 'IN_PROGRESS'].includes(job.status)) state.cancelRequestedId = null;
    state.pollError = null;
    state.scanPollFailures = 0;
    if (job.status === 'COMPLETE') {
      if (job.report) {
        state.report = job.report;
        state.findings = Array.isArray(job.report.findings) ? job.report.findings : [];
        state.visibleFindings = 100;
        renderSeverity();
        renderFindings();
        toast(job.report.scanMode === 'sbom'
          ? 'SBOM vulnerability check complete. The report is ready.'
          : 'Local Trivy image scan complete. The report is ready.');
      } else {
        await loadLatestReport();
        return;
      }
    } else if (job.status === 'FAILED' || job.status === 'CANCELED') {
      if (job.status === 'FAILED') toast(job.error?.message || 'The local Trivy check failed. Review its status and try again.', true);
      renderFindings();
    }
    renderScanStatus();
    scheduleScanPoll();
  } catch (error) {
    if (requestId !== state.findingRequestId || key !== currentScanKey() || $('findingDrawer').hidden) return;
    state.pollError = error.message;
    state.scanPollFailures += 1;
    renderScanStatus();
    if (state.scanPollFailures < 3) scheduleScanPoll();
    else toast('Could not refresh scan progress. Use Refresh to check the job again.', true);
  }
}

function csvCell(value) {
  let text = value === undefined || value === null ? '' : String(value);
  if (/^\s*[=+\-@]/.test(text) || /^[\t\r\n]/.test(text)) text = `'${text}`;
  return '"' + text.replaceAll('"', '""') + '"';
}

function exportFindings() {
  if (!state.report || !state.image || !state.repository) return;
  const report = state.report;
  const sbomReport = report.scanMode === 'sbom';
  const producer = report.provenance?.producer;
  const producerName = typeof producer === 'string' ? producer : producer?.name;
  const header = ['Report status', 'Scan input', 'Scanner', 'Scanner version', 'Database updated', 'Scanned at', 'AWS account', 'Region', 'Repository', 'Reported image digest', 'Platform', 'Normalized SBOM SHA-256', 'SBOM producer claim', 'SBOM generated at claim', 'Image association', 'Package types detected', 'Coverage note', 'Target', 'Package type', 'Severity', 'CVE / advisory ID', 'Title', 'Package', 'Installed version', 'Fixed version', 'CVSS', 'Advisory URL'];
  const rows = state.findings.length ? state.findings : [{}];
  const lines = [header, ...rows.map((finding) => [
    'COMPLETE', sbomReport ? 'Imported SBOM' : 'ECR image layers', report.source || 'Trivy', report.scannerVersion, report.dbUpdatedAt, report.scannedAt,
    report.account || state.identity?.account, report.region || state.region,
    report.repository || state.repository.name, report.digest || state.image.digest,
    report.platform || $('platformSelect').value,
    sbomReport ? report.provenance?.sbomSha256 : '', sbomReport ? producerName : '',
    sbomReport ? report.provenance?.generatedAt : '', sbomReport ? 'Unverified producer assertion' : 'Image read by Trivy',
    Array.isArray(report.coverage?.packageTypes) ? report.coverage.packageTypes.join(' + ') : '',
    report.coverage?.note || '', finding.target, finding.type,
    finding.severity, finding.id, finding.title, finding.packageName,
    finding.installedVersion, finding.fixedVersion, finding.score, safeExternalUrl(finding.uri) || '',
  ])].map((row) => row.map(csvCell).join(','));
  const blob = new Blob([`\uFEFF${lines.join('\r\n')}\r\n`], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = element('a');
  link.href = url;
  const safeRepo = state.repository.name.replaceAll('/', '-').replace(/[^a-z0-9._-]/gi, '_');
  link.download = `trivy-${sbomReport ? 'sbom' : 'image'}-report-${safeRepo}-${state.image.digest.slice(-12)}-${(report.platform || $('platformSelect').value).replace('/', '-')}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`Exported the full local report with ${state.findings.length} finding${state.findings.length === 1 ? '' : 's'}.`);
}

function showSbomImportError(message) {
  const errorLine = $('sbomImportError');
  errorLine.textContent = message;
  errorLine.hidden = false;
  errorLine.focus();
}

function validateSelectedSbomBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || bundle.schemaVersion !== 1) {
    throw new Error('Choose an ECR Sentinel SBOM bundle with schemaVersion 1. A raw SBOM needs the image identity wrapper from the build-host helper.');
  }
  const image = bundle.image;
  if (!image || typeof image !== 'object' || Array.isArray(image) ||
    image.account !== state.identity?.account || image.region !== state.region ||
    image.repository !== state.repository?.name || image.digest !== state.image?.digest ||
    image.platform !== $('platformSelect').value) {
    throw new Error('The bundle’s claimed AWS account, Region, repository, digest, or platform does not match this selected image. Choose the matching image and platform, then import again.');
  }
  if (typeof bundle.generatedAt !== 'string' || !Number.isFinite(Date.parse(bundle.generatedAt)) ||
    !bundle.producer || typeof bundle.producer.name !== 'string' || !bundle.producer.name.trim() ||
    typeof bundle.producer.trivyVersion !== 'string' || !bundle.producer.trivyVersion.trim()) {
    throw new Error('The bundle must include a valid generation time and producer details. Generate it with the ECR Sentinel build-host helper.');
  }
  const sbom = bundle.sbom;
  if (!sbom || typeof sbom !== 'object' || Array.isArray(sbom)) {
    throw new Error('The bundle does not contain a CycloneDX or SPDX JSON SBOM.');
  }
  const cyclonedx = sbom.bomFormat === 'CycloneDX' && /^1\.[4-9]$/.test(sbom.specVersion) && Array.isArray(sbom.components);
  const spdx = /^SPDX-2\.[23]$/.test(sbom.spdxVersion) && Array.isArray(sbom.packages);
  if (!cyclonedx && !spdx) {
    throw new Error('The bundle must contain CycloneDX 1.4–1.9 or SPDX 2.2/2.3 JSON with a package list.');
  }
  return cyclonedx ? 'CycloneDX' : 'SPDX';
}

async function selectSbomBundle(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  input.value = '';
  if (!file) return;
  $('sbomImportError').hidden = true;
  const button = $('importSbomButton');
  const key = currentScanKey();
  const requestId = state.findingRequestId;
  state.readingSbomFile = true;
  setLoading(button, true, 'Reading bundle…');
  renderScanStatus();
  try {
    if (!/\.json$/i.test(file.name)) throw new Error('Choose a .json SBOM bundle produced by the build-host helper.');
    if (file.size === 0) throw new Error('The selected SBOM bundle is empty.');
    if (file.size > MAX_SBOM_FILE_BYTES) throw new Error('The selected bundle exceeds the 16 MiB import limit.');
    const contents = await file.text();
    if (key !== currentScanKey() || requestId !== state.findingRequestId || $('findingDrawer').hidden) return;
    let bundle;
    try { bundle = JSON.parse(contents); }
    catch { throw new Error('The selected SBOM bundle is not valid JSON.'); }
    const format = validateSelectedSbomBundle(bundle);
    state.pendingSbomBundle = bundle;
    state.activeDialog = 'sbom';
    state.modalPriorFocus = button;
    $('confirmTitle').textContent = `Check this ${format} SBOM locally?`;
    $('confirmText').textContent = 'Trivy will check packages recorded in this SBOM without downloading image layers. The bundle claims to match the selected image and platform, but its producer and image association have not been cryptographically verified. Continue only if you trust its source.';
    $('confirmTarget').textContent = `${file.name} · ${state.repository.name}@${state.image.digest} · ${$('platformSelect').value}`;
    $('cancelScanButton').textContent = 'Cancel';
    $('confirmScanButton').textContent = 'Check SBOM with Trivy';
    $('confirmModal').hidden = false;
    $('confirmBackdrop').hidden = false;
    $('confirmScanButton').focus();
  } catch (error) {
    if (key === currentScanKey() && requestId === state.findingRequestId && !$('findingDrawer').hidden) {
      showSbomImportError(error.message || 'Could not read this SBOM bundle. Choose a valid JSON file and try again.');
    }
  } finally {
    state.readingSbomFile = false;
    setLoading(button, false);
    renderScanStatus();
  }
}

function openScanConfirmation() {
  if (!state.image || !state.repository || !state.scanner.available || state.image.status === 'ARCHIVED' ||
    ['PENDING', 'IN_PROGRESS'].includes(state.scanJob?.status) || state.readingSbomFile) return;
  state.activeDialog = 'start';
  state.modalPriorFocus = document.activeElement;
  $('confirmTitle').textContent = state.report || state.scanJob?.status === 'COMPLETE' ? 'Rescan this image locally?' : 'Scan this image locally?';
  $('confirmText').textContent = 'Trivy will transfer image layers from ECR to this Mac for the selected platform. This requires ECR image-pull permissions; some files may be stored temporarily during analysis. Trivy may also download vulnerability database updates. ECR managed scanning is not started.';
  $('confirmTarget').textContent = `${state.repository.name}@${state.image.digest} · ${$('platformSelect').value}`;
  $('cancelScanButton').textContent = 'Cancel';
  $('confirmScanButton').textContent = 'Start Trivy scan';
  $('confirmModal').hidden = false;
  $('confirmBackdrop').hidden = false;
  renderScanStatus();
  $('confirmScanButton').focus();
}

function openCancelConfirmation() {
  if (!state.scanJob?.id || !['PENDING', 'IN_PROGRESS'].includes(state.scanJob.status)) return;
  state.activeDialog = 'cancel';
  state.modalPriorFocus = document.activeElement;
  $('confirmTitle').textContent = state.scanJob.mode === 'sbom' ? 'Cancel this SBOM check?' : 'Cancel this local image scan?';
  $('confirmText').textContent = 'The Trivy process will stop. An earlier completed report, if available, will remain visible in this app session.';
  $('confirmTarget').textContent = `${state.repository.name}@${state.image.digest} · ${$('platformSelect').value}`;
  $('cancelScanButton').textContent = 'Keep scanning';
  $('confirmScanButton').textContent = 'Cancel scan';
  $('confirmModal').hidden = false;
  $('confirmBackdrop').hidden = false;
  renderScanStatus();
  $('confirmScanButton').focus();
}

function closeScanConfirmation() {
  $('confirmModal').hidden = true;
  $('confirmBackdrop').hidden = true;
  state.activeDialog = null;
  state.pendingSbomBundle = null;
  if (!$('findingDrawer').hidden) renderScanStatus();
  if (state.modalPriorFocus?.isConnected) state.modalPriorFocus.focus();
}

async function confirmScan() {
  if (state.activeDialog === 'cancel') return confirmCancelScan();
  if (state.activeDialog === 'sbom') return confirmSbomScan();
  if (!state.image || !state.repository) return;
  const button = $('confirmScanButton');
  const key = currentScanKey();
  const requestId = state.findingRequestId;
  setLoading(button, true, 'Starting…');
  try {
    const job = await api('/api/scans', {
      method: 'POST',
      body: JSON.stringify({
        profile: state.profile, region: state.region,
        repository: state.repository.name, digest: state.image.digest,
        platform: $('platformSelect').value,
      }),
    });
    closeScanConfirmation();
    toast('Trivy scan started on this Mac. You can close the report while it runs.');
    if (key === currentScanKey() && requestId === state.findingRequestId && !$('findingDrawer').hidden) {
      state.scanJob = job;
      state.scanPollFailures = 0;
      state.pollError = null;
      state.cancelRequestedId = null;
      renderScanStatus();
      renderFindings();
      scheduleScanPoll();
    }
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function confirmSbomScan() {
  const bundle = state.pendingSbomBundle;
  if (!bundle || !state.image || !state.repository) return;
  const button = $('confirmScanButton');
  const key = currentScanKey();
  const requestId = state.findingRequestId;
  setLoading(button, true, 'Starting…');
  try {
    const job = await api('/api/scans/sbom', {
      method: 'POST',
      body: JSON.stringify({
        profile: state.profile, region: state.region, repository: state.repository.name,
        digest: state.image.digest, platform: $('platformSelect').value, bundle,
      }),
    });
    closeScanConfirmation();
    toast('SBOM vulnerability check started on this Mac. No image layers are downloaded.');
    if (key === currentScanKey() && requestId === state.findingRequestId && !$('findingDrawer').hidden) {
      state.scanJob = job;
      state.scanPollFailures = 0;
      state.pollError = null;
      state.cancelRequestedId = null;
      renderScanStatus();
      renderFindings();
      scheduleScanPoll();
    }
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

async function confirmCancelScan() {
  const jobId = state.scanJob?.id;
  if (!jobId) return;
  const key = currentScanKey();
  const button = $('confirmScanButton');
  setLoading(button, true, 'Canceling…');
  try {
    const job = await api(`/api/scans/${encodeURIComponent(jobId)}`, { method: 'DELETE' });
    closeScanConfirmation();
    if (key === currentScanKey() && state.scanJob?.id === jobId) {
      clearTimeout(state.scanPollTimer);
      state.scanPollTimer = null;
      state.scanJob = job;
      state.pollError = null;
      state.cancelRequestedId = ['PENDING', 'IN_PROGRESS'].includes(job.status) ? jobId : null;
      renderScanStatus();
      renderFindings();
      if (['PENDING', 'IN_PROGRESS'].includes(job.status)) scheduleScanPoll();
    }
    toast(job.status === 'CANCELED' ? 'Local scan canceled.' : 'Cancellation requested. Waiting for Trivy to stop.');
  } catch (error) {
    if (error.code === 'INVALID_API_TOKEN') return;
    toast(error.message, true);
  } finally {
    setLoading(button, false);
  }
}

function openSidebar() {
  $('sidebar').classList.add('open');
  $('sidebarScrim').hidden = false;
  $('closeSidebar').focus();
}

function closeSidebar() {
  $('sidebar').classList.remove('open');
  $('sidebarScrim').hidden = true;
}

function trapDialogFocus(event) {
  if (event.key !== 'Tab') return;
  const root = !$('confirmModal').hidden ? $('confirmModal') : !$('findingDrawer').hidden ? $('findingDrawer') : null;
  if (!root) return;
  const controls = [...root.querySelectorAll('button:not([disabled]):not([hidden]), input:not([disabled]):not([tabindex="-1"]), select:not([disabled]), a[href]')]
    .filter((item) => item.offsetParent !== null);
  if (!controls.length) return;
  const first = controls[0];
  const last = controls.at(-1);
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}

function changeConnection() {
  state.roleMfaRequestId += 1;
  $('roleMfaCode').value = '';
  state.connectionId += 1;
  state.repositoryRequestId += 1;
  state.requestId += 1;
  state.findingRequestId += 1;
  sessionStorage.removeItem('ecr-sentinel-connection');
  state.identity = null;
  state.repository = null;
  state.repositories = [];
  state.images = [];
  closeDrawer();
  showSetup();
  $('profileSelect').focus();
}

function init() {
  $('lockTabButton').addEventListener('click', () => {
    apiToken = '';
    try {
      sessionStorage.removeItem(tokenStorageKey);
      sessionStorage.removeItem('ecr-sentinel-connection');
    } catch { /* The in-memory token is cleared even if storage is unavailable. */ }
    showLaunchGate();
    $('launchGateTitle').focus();
  });
  if (!apiToken) { showLaunchGate(); return; }
  showSetup();
  loadScannerStatus();
  $('checkScannerButton').addEventListener('click', loadScannerStatus);
  $('copyInstallCommand').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText('brew install trivy');
      toast('Trivy install command copied. Run it in Terminal.');
    } catch {
      toast('Could not copy the command. Select the text and copy it manually.', true);
    }
  });
  $('connectionForm').addEventListener('submit', (event) => {
    event.preventDefault();
    connect($('profileSelect').value, $('regionInput').value.trim());
  });
  $('profileSelect').addEventListener('change', () => {
    $('connectionError').hidden = true;
    loadAuthMethod($('profileSelect').value);
  });
  $('regionInput').addEventListener('input', () => {
    state.roleMfaRequestId += 1;
    $('roleMfaCode').value = '';
    $('roleMfaError').hidden = true;
    renderAuthHelp();
  });
  $('authHelpToggle').addEventListener('click', () => setAuthHelpOpen($('authHelp').hidden));
  $('submitRoleMfaButton').addEventListener('click', authenticateRoleMfa);
  $('roleMfaCode').addEventListener('input', () => { $('roleMfaError').hidden = true; });
  $('roleMfaCode').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') { event.preventDefault(); authenticateRoleMfa(); }
  });
  $('copyAuthCommand').addEventListener('click', async () => {
    const command = $('authCommand').textContent;
    if (!$('profileSelect').value || !command) return;
    try {
      await navigator.clipboard.writeText(command);
      toast('AWS CLI command copied. Run it in Terminal.');
    } catch {
      toast('Could not copy the command. Select the text and copy it manually.', true);
    }
  });
  $('refreshProfilesButton').addEventListener('click', async () => {
    const button = $('refreshProfilesButton');
    setLoading(button, true, 'Refreshing…');
    try { await loadProfiles({ refresh: true }); }
    finally { setLoading(button, false); }
  });
  $('retryConnectionButton').addEventListener('click', () => {
    connect($('profileSelect').value, $('regionInput').value.trim());
  });
  $('changeConnectionButton').addEventListener('click', changeConnection);
  $('drawerChangeConnectionButton').addEventListener('click', changeConnection);
  $('scanSwitchProfileButton').addEventListener('click', changeConnection);
  $('refreshButton').addEventListener('click', () => state.repository ? loadImages() : loadRepositories());
  $('repoSearch').addEventListener('input', () => { renderRepositoryNavigation(); if (!state.repository) renderRepositoryGrid(); });
  $('loadMoreRepos').addEventListener('click', () => loadRepositories(true));
  $('imageSearch').addEventListener('input', renderImages);
  $('imageSort').addEventListener('change', renderImages);
  $('loadMoreImages').addEventListener('click', () => loadImages(true));
  $('drawerBackdrop').addEventListener('click', closeDrawer);
  $('closeDrawer').addEventListener('click', closeDrawer);
  $('platformSelect').addEventListener('change', () => {
    state.report = null;
    state.findings = [];
    state.visibleFindings = 100;
    state.scanJob = null;
    state.reportError = null;
    state.pollError = null;
    state.pendingSbomBundle = null;
    $('sbomImportError').hidden = true;
    renderSeverity();
    renderFindings();
    loadLatestReport();
  });
  $('findingSearch').addEventListener('input', () => { state.visibleFindings = 100; renderFindings(); });
  $('severityFilter').addEventListener('change', () => { state.visibleFindings = 100; renderFindings(); });
  $('loadMoreFindings').addEventListener('click', () => { state.visibleFindings += 100; renderFindings(); });
  $('refreshFindingsButton').addEventListener('click', loadLatestReport);
  $('exportButton').addEventListener('click', exportFindings);
  $('importSbomButton').addEventListener('click', () => {
    $('sbomImportError').hidden = true;
    $('sbomFileInput').click();
  });
  $('sbomFileInput').addEventListener('change', selectSbomBundle);
  $('startScanButton').addEventListener('click', openScanConfirmation);
  $('cancelRunningScanButton').addEventListener('click', openCancelConfirmation);
  $('confirmBackdrop').addEventListener('click', closeScanConfirmation);
  $('cancelScanButton').addEventListener('click', closeScanConfirmation);
  $('confirmScanButton').addEventListener('click', confirmScan);
  $('openSidebar').addEventListener('click', openSidebar);
  $('closeSidebar').addEventListener('click', closeSidebar);
  $('sidebarScrim').addEventListener('click', closeSidebar);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (!$('confirmModal').hidden) closeScanConfirmation();
      else if (!$('findingDrawer').hidden) closeDrawer();
      else closeSidebar();
    }
    trapDialogFocus(event);
  });
  loadProfiles();
}

init();
