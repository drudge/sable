export const meta = {
  name: 'feature-build',
  description: 'Build a Sable feature plan Nick approved: slices in parallel worktrees, merged wave by wave, then checked by tests, the Vandelay demo, and a review panel, and opened as a PR',
  whenToUse: 'Only after Nick approves a feature plan in chat. Args: the plan object described at the top of the script. Add ship: false to stop before the push and PR.',
  phases: [
    { title: 'Prepare', detail: 'plan checks, the feature branch, and tools' },
    { title: 'Build', detail: 'each slice in its own worktree, merged wave by wave' },
    { title: 'Check', detail: 'mage verify, browser tests, demo screenshots, and a review panel' },
    { title: 'Verify', detail: 'a skeptic on every review finding' },
    { title: 'Fix', detail: 'confirmed problems fixed and rechecked, two rounds at most' },
    { title: 'Ship', detail: 'a PR, never merged' },
  ],
}

// The plan is what Nick approved in chat, passed as args:
//
//   {
//     feature: 'Insights device search',
//     branch: 'claude/insights-device-search',    // optional; the current branch otherwise
//     goal: 'What it does for someone using Sable.',
//     decisions: ['Search lives in the page address.'],    // Nick's calls; binding
//     slices: [
//       { id: 'query', title: 'Filter devices in the store', owns: ['internal/insights/devices/'],
//         done: ['Filters by name, hardware address, IP, maker, and type', 'Table tests'] },
//       { id: 'ui', title: 'Search box and filters on Devices', owns: ['internal/web/pages/insights'],
//         done: ['...'], dependsOn: ['query'], pages: ['/insights?tab=devices'] },
//     ],
//     ship: true,    // false stops before the push and PR
//   }
//
// A slice starts once everything it depends on has merged, and two slices that
// own overlapping paths never build at the same time. The approved design is
// binding: a slice that can't finish without changing it stops and asks.

const plan = args || {}
const slices = Array.isArray(plan.slices) ? plan.slices : []
const decisions = Array.isArray(plan.decisions) ? plan.decisions : []
const problems = []
if (!plan.feature || !plan.goal) problems.push('The plan needs a feature name and a goal.')
if (!slices.length) problems.push('The plan needs at least one slice.')
const ids = new Set()
for (const slice of slices) {
  if (!slice.id || !slice.title || !(slice.owns || []).length || !(slice.done || []).length) problems.push(`Slice "${slice.id || slice.title || '?'}" needs an id, a title, the paths it owns, and what done means.`)
  if (ids.has(slice.id)) problems.push(`Two slices are called ${slice.id}.`)
  ids.add(slice.id)
}
for (const slice of slices) for (const dependency of slice.dependsOn || []) if (!ids.has(dependency)) problems.push(`${slice.id} depends on ${dependency}, which isn't a slice.`)
if (problems.length) return { status: 'blocked', blockers: problems }

// Waves: each takes the slices whose dependencies landed in earlier waves,
// holding back any that owns a path another slice in the wave owns.
const overlaps = (a, b) => a.owns.some(one => b.owns.some(other => one.startsWith(other) || other.startsWith(one)))
const waves = []
const scheduled = new Set()
let waiting = [...slices]
while (waiting.length) {
  const wave = []
  for (const slice of waiting) {
    if ((slice.dependsOn || []).every(dependency => scheduled.has(dependency)) && !wave.some(other => overlaps(other, slice))) wave.push(slice)
  }
  if (!wave.length) return { status: 'blocked', blockers: [`These slices depend on each other in a circle: ${waiting.map(slice => slice.id).join(', ')}.`] }
  for (const slice of wave) scheduled.add(slice.id)
  waves.push(wave)
  waiting = waiting.filter(slice => !wave.includes(slice))
}
const slug = String(plan.feature).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
const work = `_work/feature-${slug}`
const allPages = [...new Set(slices.flatMap(slice => slice.pages || []))]
const doneItems = slices.flatMap(slice => slice.done.map(item => `${slice.id}: ${item}`))
const context = `"${plan.feature}" for Sable. The goal: ${plan.goal}${decisions.length ? `\nNick's decisions, which are binding:\n${decisions.map(decision => `- ${decision}`).join('\n')}` : ''}`
log(`${slices.length} slice(s) in ${waves.length} wave(s): ${waves.map(wave => wave.map(slice => slice.id).join(' + ')).join(', then ')}.`)

const text = { type: 'string' }
const texts = { type: 'array', items: text }
const FINDING = {
  type: 'object',
  properties: {
    area: text,
    where: { type: 'string', description: 'file:line, or page, size, and theme' },
    problem: text,
    evidence: { type: 'string', description: 'The code, output, or screenshot detail that shows it' },
    fix: { type: 'string', enum: ['mechanical', 'needs-nick'] },
    suggestion: text,
  },
  required: ['area', 'where', 'problem', 'evidence', 'fix', 'suggestion'],
}
const FINDINGS = { type: 'object', properties: { findings: { type: 'array', items: FINDING } }, required: ['findings'] }
const PREPARE = { type: 'object', properties: { ok: { type: 'boolean' }, blockers: texts, branch: text, base: { type: 'string', description: 'Short hash of HEAD' } }, required: ['ok', 'blockers', 'branch', 'base'] }
const SLICE = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['done', 'blocked'] },
    branch: text,
    worktree: { type: 'string', description: 'Absolute path of your worktree' },
    commits: texts,
    touchedOutside: { type: 'array', items: text, description: 'Files you changed outside what the slice owns' },
    tests: { type: 'array', items: text, description: 'The test commands you ran, all passing' },
    question: { type: 'string', description: 'For blocked, the question for Nick; otherwise empty' },
    notes: text,
  },
  required: ['status', 'branch', 'worktree', 'commits', 'touchedOutside', 'tests', 'question', 'notes'],
}
const MERGED = {
  type: 'object',
  properties: {
    head: { type: 'string', description: 'Short hash of HEAD after the merges' },
    merged: texts,
    failed: { type: 'array', items: { type: 'object', properties: { branch: text, reason: text }, required: ['branch', 'reason'] } },
    testsOk: { type: 'boolean' },
    testOutput: text,
  },
  required: ['head', 'merged', 'failed', 'testsOk', 'testOutput'],
}
const CHECKS = { type: 'object', properties: { ok: { type: 'boolean' }, failures: { type: 'array', items: { type: 'object', properties: { check: text, message: text }, required: ['check', 'message'] } } }, required: ['ok', 'failures'] }
const SHOTS = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    blocker: { type: 'string', description: 'Why no screenshots were taken, or empty' },
    shots: { type: 'array', items: { type: 'object', properties: { page: text, viewport: text, theme: text, file: text, problems: texts }, required: ['page', 'viewport', 'theme', 'file', 'problems'] } },
  },
  required: ['ok', 'blocker', 'shots'],
}
const REAL = { type: 'object', properties: { real: { type: 'boolean' }, reason: text }, required: ['real', 'reason'] }
const FIXED = {
  type: 'object',
  properties: {
    fixed: { type: 'array', items: { type: 'object', properties: { id: text, change: text }, required: ['id', 'change'] } },
    notFixed: { type: 'array', items: { type: 'object', properties: { id: text, reason: text }, required: ['id', 'reason'] } },
  },
  required: ['fixed', 'notFixed'],
}
const STILL = { type: 'object', properties: { open: { type: 'array', items: { type: 'object', properties: { id: text, why: text }, required: ['id', 'why'] } } }, required: ['open'] }
const SHIPPED = { type: 'object', properties: { pr: text, cleaned: texts }, required: ['pr', 'cleaned'] }

phase('Prepare')
const prep = await agent(`Get ready to build ${context}

The current directory is a checkout of drudge/sable. Use shell commands.
1. Run \`git fetch origin\`. The checkout must be clean.
2. ${plan.branch ? `Switch to ${plan.branch}, creating it from origin/main if it doesn't exist.` : `Stay on the current branch. If it is main, create claude/${slug} from it.`} It must contain origin/main; if it doesn't, run \`git merge origin/main\` (never rebase) and note it.
3. \`go tool mage build\` must pass here. A broken starting point is a blocker.
4. If scripts/browser/node_modules is missing, run \`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --prefix scripts/browser\`.
${allPages.length ? '5. The Vandelay demo\'s ports must be free for the screenshots later: nothing listening on TCP 5391-5393, 5491-5493, or 8555-8557 (check with lsof). If one is busy, add the blocker "A Vandelay demo is running on <ports>. Stop it, then run this again." Never stop it yourself.\n' : ''}branch is the branch you ended on, and base is \`git rev-parse --short=12 HEAD\`. ok is true only when there are no blockers.`, { label: 'prepare', phase: 'Prepare', schema: PREPARE, effort: 'low' })
if (!prep || !prep.ok) return { status: 'blocked', blockers: prep ? prep.blockers : ['The prepare step did not finish.'] }
const branch = prep.branch

phase('Build')
const unfinished = []
const needsNick = []
const results = new Map()
const merged = new Set()
const skipped = []
const findings = []
let base = prep.base
for (const [index, wave] of waves.entries()) {
  const runnable = wave.filter(slice => (slice.dependsOn || []).every(dependency => merged.has(dependency)))
  for (const slice of wave.filter(slice => !runnable.includes(slice))) {
    skipped.push({ id: slice.id, reason: `It needs ${(slice.dependsOn || []).filter(dependency => !merged.has(dependency)).join(', ')}, which didn't land.` })
  }
  if (!runnable.length) continue
  const built = await parallel(runnable.map(slice => () => agent(`You are building one slice of ${context}

Your slice is ${slice.id}: ${slice.title}.
It owns ${slice.owns.join(', ')}. Stay inside those paths. If you must touch anything else, such as a route table or a shared type, keep that edit as small as you can and list it in touchedOutside.
Done means:
${slice.done.map(item => `- ${item}`).join('\n')}
${(slice.dependsOn || []).length ? `It builds on ${slice.dependsOn.join(', ')}, already merged at ${base}.\n` : ''}${runnable.length > 1 ? `Other slices are being built at the same time (${runnable.filter(other => other !== slice).map(other => `${other.id}: ${other.title}`).join('; ')}). Don't do their work.\n` : ''}
You are in your own git worktree. Work only there.
1. Start your branch at the feature's current state: \`git checkout -B ${branch}-${slice.id} ${base}\`.
2. Build it the way the surrounding code is written, with tests beside the code. After editing .templ files, run \`go tool mage generate\` and commit the generated files too.
3. Run \`GOEXPERIMENT=jsonv2 go test\` and \`go vet\` for every package you touched. They must pass.
4. Commit each separate change on its own with a plain one-line message. Don't push.
5. If the plan is wrong, can't be done, or would need a different design to finish, stop and return blocked with the question for Nick. Don't improvise a different design.`, { label: `build ${slice.id}`, phase: 'Build', schema: SLICE, isolation: 'worktree' })))
  const landed = []
  built.forEach((result, position) => {
    const slice = runnable[position]
    if (!result) {
      unfinished.push(`Building ${slice.id} did not finish.`)
    } else if (result.status === 'blocked') {
      results.set(slice.id, result)
      needsNick.push({ area: 'plan', where: `slice ${slice.id}`, problem: result.question, evidence: result.notes, fix: 'needs-nick', suggestion: 'Answer it, then run the workflow again.' })
    } else {
      results.set(slice.id, result)
      landed.push({ slice, result })
    }
  })
  if (!landed.length) continue
  const merge = await agent(`Merge these slice branches into ${branch} in this checkout, one at a time, in this order: ${landed.map(({ result }) => result.branch).join(', ')}. Use \`git merge --no-ff\` so each slice stays visible in the history. Resolve a conflict by keeping what both slices meant; if it needs a design choice, abort that merge and report it.
After each merge, run \`go tool mage generate\` if templ files changed and commit anything it regenerates, then \`go build ./...\`.
When they are all in, run \`GOEXPERIMENT=jsonv2 go test\` for the packages these slices touched. Don't fix failures here; report them.`, { label: `merge wave ${index + 1}`, phase: 'Build', schema: MERGED })
  if (!merge) {
    unfinished.push(`Merging wave ${index + 1} did not finish, so the build stopped there.`)
    break
  }
  for (const { slice, result } of landed) {
    const failure = merge.failed.find(item => item.branch === result.branch)
    if (failure) needsNick.push({ area: 'plan', where: `slice ${slice.id}`, problem: `It didn't merge: ${failure.reason}`, evidence: result.branch, fix: 'needs-nick', suggestion: 'Decide how the slices fit together.' })
    else merged.add(slice.id)
  }
  if (!merge.testsOk) findings.push({ area: 'tests', where: `after wave ${index + 1}`, problem: 'Tests fail after the merge.', evidence: merge.testOutput, fix: 'mechanical', suggestion: 'Fix the cause.' })
  base = merge.head
  log(`Wave ${index + 1} merged: ${merge.merged.join(', ') || 'nothing'}.`)
}
if (!merged.size) return { status: 'needs-attention', stoppedAt: 'build', branch, needsNick, skipped, unfinished }

const landedSlices = slices.filter(slice => merged.has(slice.id))
const pages = [...new Set(landedSlices.flatMap(slice => slice.pages || []))]
const touchesWeb = landedSlices.some(slice => slice.owns.some(owned => owned.startsWith('internal/web') || owned.startsWith('scripts/browser'))) || [...results.values()].some(result => (result.touchedOutside || []).some(file => file.startsWith('internal/web')))
const verifyPrompt = `In this checkout, run \`go tool mage verify\` with a 15-minute timeout. Report each failure with the output that shows it. Don't change files.`
const browserPrompt = `In this checkout, run \`GOEXPERIMENT=jsonv2 go test -count=1 -tags=browser -run TestBrowser -v ./internal/web\` with a 10-minute timeout. Playwright is installed under scripts/browser. Report each failing test with its output. Don't change files.`
const houseRules = [
  'On a phone, a dialog stacks its buttons with the main action on top and Cancel, Close, or Done at the bottom.',
  'No action buttons sit beside a drawer\'s or dialog\'s close button; they go next to the content they act on, with a text label.',
  'Controls that only matter when a switch is on stay folded away while it is off, help text stays short, and each button does one job.',
  'The whole sidebar fits a 1218x787 window, and button labels stay on one line.',
  'Labels, buttons, titles, and tabs use Title Case; descriptions, help, and messages use sentence case with a period.',
  'Destructive buttons are outlined red on pages, cards, and rows, and solid red only as the final button of a confirm dialog.',
]
const lookPrompt = shots => `Look at these screenshots of ${context}

They are the pages the feature touches on the Vandelay demo, at Nick's 1218x787 laptop size and a 390px phone, in dark and light:
${shots.map(shot => `- ${shot.file} (${shot.page}, ${shot.viewport}, ${shot.theme})${shot.problems.length ? `; measured problems: ${shot.problems.join('; ')}` : ''}`).join('\n')}

Report what looks broken or off: clipped or overlapping text, controls that wrap or overflow, sideways scrolling, empty or loading states where there should be data, light and dark disagreeing, and anything that breaks docs/ui.md or these house rules:
${houseRules.map(rule => `- ${rule}`).join('\n')}
Each finding names the file, and whether it's mechanical (a clear fix that keeps the design) or needs-nick (a design call). Don't change files.`
const shotsPrompt = list => `In this checkout, run \`node scripts/browser/screenshots.cjs --demo --pages '${list.join(',')}' --out ${work}/shots\` with a 15-minute timeout. It builds the code, starts the Vandelay demo, photographs each page, and always stops the demo. It prints JSON; turn each shot into one entry, listing its measured problems (sideways scrolling, errors, failed requests). If it refuses because a demo is already running, don't stop that demo; return the message as blocker.`
const lookAtPages = async (list, round) => {
  const shots = await agent(shotsPrompt(list), { label: round ? `screenshots ${round}` : 'screenshots', phase: round ? 'Fix' : 'Check', schema: SHOTS, effort: 'low' })
  if (!shots) return { unfinished: 'The screenshot step did not finish.' }
  if (shots.blocker) return { unfinished: `No screenshots: ${shots.blocker}` }
  const look = await agent(lookPrompt(shots.shots), { label: round ? `look ${round}` : 'look at the pages', phase: round ? 'Fix' : 'Check', schema: FINDINGS })
  return look ? { look } : { unfinished: 'The screenshot review did not finish.' }
}
const REVIEWERS = [
  { key: 'correctness', focus: 'bugs: wrong logic, missed edge cases, error handling, races, and tests that pass without proving the behavior' },
  { key: 'security', focus: 'permissions on new routes and actions, input validation, CSRF on posts, escaping in templates, secrets in logs or config, and anything a replica or an API token could misuse' },
  { key: 'plan', focus: `whether it does what the plan says and nothing more: every done item (${doneItems.join('; ')}), Nick's decisions, and no design swapped or added without him` },
  { key: 'conventions', focus: 'docs/ui.md and the console\'s existing patterns, docs and config.example.toml for anything new, and code that reads like the code around it' },
]
const reviewPrompt = reviewer => `Review the changes for ${context}

Read \`git diff ${prep.base}..HEAD\` on ${branch} in this checkout, and the code around it. Look only for ${reviewer.focus}. Report real problems with file:line and the evidence, not style nits. Each finding is mechanical (a clear fix that keeps the design) or needs-nick (it needs a design or product call). Don't change files.`

phase('Check')
// mage verify regenerates templ files, so it runs alone before anything builds.
const verify = await agent(verifyPrompt, { label: 'mage verify', phase: 'Check', schema: CHECKS, effort: 'low' })
if (!verify) unfinished.push('mage verify did not finish.')
const [browserTests, pageLook, ...reviews] = await parallel([
  async () => touchesWeb ? agent(browserPrompt, { label: 'browser tests', phase: 'Check', schema: CHECKS, effort: 'low' }) : null,
  async () => pages.length ? lookAtPages(pages) : null,
  ...REVIEWERS.map(reviewer => () => agent(reviewPrompt(reviewer), { label: `review: ${reviewer.key}`, phase: 'Check', schema: FINDINGS })),
])
const checkFindings = (result, name) => (result?.failures || []).map(failure => ({ area: name, where: failure.check, problem: `${name} fails.`, evidence: failure.message, fix: 'mechanical', suggestion: 'Fix the cause.' }))
findings.push(...checkFindings(verify, 'mage verify'), ...checkFindings(browserTests, 'browser tests'))
if (touchesWeb && !browserTests) unfinished.push('The browser tests did not finish.')
if (pageLook?.unfinished) unfinished.push(pageLook.unfinished)
REVIEWERS.forEach((reviewer, position) => {
  if (!reviews[position]) unfinished.push(`The ${reviewer.key} review did not finish.`)
})
const reviewFindings = [...(pageLook?.look?.findings || []).map(finding => ({ ...finding, area: `look: ${finding.area}` })), ...reviews.filter(Boolean).flatMap(review => review.findings)]
// Two reviewers often report the same problem; keep one.
const seen = new Set()
const distinct = reviewFindings.filter(finding => {
  const key = `${finding.where}|${finding.problem}`.toLowerCase()
  if (seen.has(key)) return false
  seen.add(key)
  return true
})
log(`${distinct.length} review finding(s) to verify, ${findings.length} failing check(s).`)

phase('Verify')
const verdicts = await pipeline(distinct, finding => agent(`A reviewer reported this about ${context}

${JSON.stringify(finding, null, 1)}

Try to prove it isn't real. Read the code at ${finding.where}${finding.area.startsWith('look') ? ' or open the screenshot it names' : ''}, and reproduce it with a test or a command if you can. Say real only if you confirmed it yourself. Don't change files.`, { label: `skeptic: ${finding.where}`, phase: 'Verify', schema: REAL }))
const confirmed = []
distinct.forEach((finding, position) => {
  const verdict = verdicts[position]
  if (!verdict) unfinished.push(`The skeptic for "${finding.problem}" did not finish.`)
  if (!verdict || verdict.real) confirmed.push({ ...finding, evidence: verdict ? `${finding.evidence} Confirmed: ${verdict.reason}` : finding.evidence })
})
needsNick.push(...confirmed.filter(finding => finding.fix === 'needs-nick'))
findings.push(...confirmed.filter(finding => finding.fix === 'mechanical'))
log(`${confirmed.length} of ${distinct.length} review finding(s) held up; ${findings.length} to fix.`)

phase('Fix')
// remaining is what is still broken after the latest round. Anything the fixer
// declines goes to Nick, except a failing check, which stays broken.
let remaining = findings
let lastVerify = verify
const fixed = []
for (let round = 1; round <= 2 && remaining.length; round++) {
  const numbered = remaining.map((finding, position) => ({ id: `p${position + 1}`, ...finding }))
  const result = await agent(`Fix these confirmed problems in ${context}

You are on ${branch} in this checkout. Make the smallest change that fixes each one and keep the approved design. After editing .templ files, run \`go tool mage generate\`. Run the tests for what you touched. Commit each fix on its own with a message that starts with "Fix". If a fix needs a design or product call, don't make it; list it under notFixed. Answer with each problem's id.

Problems:
${JSON.stringify(numbered, null, 1)}`, { label: `fix round ${round}`, phase: 'Fix', schema: FIXED })
  if (!result) {
    unfinished.push(`Fix round ${round} did not finish.`)
    break
  }
  const fixedIds = new Set(result.fixed.map(item => item.id))
  const declinedIds = new Set(result.notFixed.map(item => item.id))
  for (const item of result.fixed) fixed.push({ where: numbered.find(finding => finding.id === item.id)?.where || item.id, change: item.change })
  for (const item of result.notFixed) {
    const finding = numbered.find(candidate => candidate.id === item.id)
    if (finding && !['mage verify', 'browser tests', 'tests'].includes(finding.area)) needsNick.push({ ...finding, evidence: `${finding.evidence} The fixer: ${item.reason}` })
  }
  const recheck = numbered.filter(finding => fixedIds.has(finding.id) && !['mage verify', 'browser tests', 'tests'].includes(finding.area))
  const reverify = await agent(verifyPrompt, { label: `mage verify ${round}`, phase: 'Fix', schema: CHECKS, effort: 'low' })
  const lookAgain = pages.length && recheck.some(finding => finding.area.startsWith('look'))
  const [rebrowse, relook, still] = await parallel([
    async () => touchesWeb ? agent(browserPrompt, { label: `browser tests ${round}`, phase: 'Fix', schema: CHECKS, effort: 'low' }) : null,
    async () => lookAgain ? lookAtPages(pages, round) : null,
    async () => recheck.length ? agent(`These problems in ${context} were just fixed on ${branch} in this checkout. For each, check the current code${lookAgain ? ' and the new screenshots' : ''} and say whether it is still there. Don't change files.

${JSON.stringify(recheck, null, 1)}`, { label: `recheck ${round}`, phase: 'Fix', schema: STILL }) : null,
  ])
  lastVerify = reverify
  const openIds = new Set((still?.open || []).map(item => item.id))
  // Checks run again; anything else stays open unless it was fixed and the
  // recheck agrees, or the fixer declined it.
  remaining = [
    ...(reverify ? checkFindings(reverify, 'mage verify') : numbered.filter(finding => finding.area === 'mage verify' || finding.area === 'tests')),
    ...(touchesWeb ? (rebrowse ? checkFindings(rebrowse, 'browser tests') : numbered.filter(finding => finding.area === 'browser tests')) : []),
    ...(relook?.look?.findings || []).filter(finding => finding.fix === 'mechanical').map(finding => ({ ...finding, area: `look: ${finding.area}` })),
    ...numbered.filter(finding => !['mage verify', 'browser tests', 'tests'].includes(finding.area) && !declinedIds.has(finding.id) && (!fixedIds.has(finding.id) || !still || openIds.has(finding.id))),
  ].map(({ id, ...finding }) => finding)
  if (relook?.unfinished) unfinished.push(`Round ${round}: ${relook.unfinished}`)
  log(remaining.length ? `Round ${round} left ${remaining.length} problem(s).` : `Round ${round} fixed everything.`)
}
const ready = !remaining.length && !unfinished.length && Boolean(lastVerify?.ok) && !skipped.length && merged.size === slices.length

let shipped = null
if (plan.ship !== false) {
  phase('Ship')
  shipped = await agent(`Ship ${context}

Never merge anything.
1. Push ${branch} with \`git push -u origin ${branch}\`.
2. Open a PR on drudge/sable against main${ready ? '' : ' as a draft, because something below is unresolved'}. Title it the way recent PRs are titled: a plain sentence saying what it does. The body says what it does for someone using Sable, the slices and their commits, the checks that ran, what was fixed after review, and what still needs Nick.${pages.length ? ` Say the screenshots are in ${work}/shots on this machine; don't upload them.` : ''}
3. Remove each slice's worktree and local branch once its branch is merged into ${branch} (\`git worktree remove\`, then \`git branch -d\`). Never delete anything that isn't merged.

Slices merged: ${[...merged].join(', ') || 'none'}
Slices blocked or skipped: ${JSON.stringify([...needsNick.filter(item => item.area === 'plan').map(item => `${item.where}: ${item.problem}`), ...skipped.map(item => `${item.id}: ${item.reason}`)])}
Fixed after review: ${JSON.stringify(fixed.map(item => `${item.where}: ${item.change}`))}
Still needs Nick: ${JSON.stringify(needsNick.map(item => `${item.where}: ${item.problem}`))}
Still broken: ${JSON.stringify(remaining.map(item => `${item.where}: ${item.problem}`))}
Didn't finish: ${JSON.stringify(unfinished)}

Return the PR URL and what you cleaned up.`, { label: 'push and PR', phase: 'Ship', schema: SHIPPED })
  if (!shipped) unfinished.push('The ship step did not finish.')
}

return {
  status: ready && (shipped || plan.ship === false) ? 'ready' : 'needs-attention',
  branch,
  pr: shipped ? shipped.pr : (plan.ship === false ? 'Not shipped (ship: false). The work is on the branch in this checkout, and the slice worktrees are still there.' : 'The ship step did not finish.'),
  slices: { merged: [...merged], blocked: [...results.entries()].filter(([, result]) => result.status === 'blocked').map(([id, result]) => ({ id, question: result.question })), skipped },
  waves: waves.map(wave => wave.map(slice => slice.id)),
  screenshots: pages.length ? `${work}/shots` : null,
  fixed,
  needsNick,
  stillBroken: remaining,
  unfinished,
}
