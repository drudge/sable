export const meta = {
  name: 'release-notes',
  description: 'Write the notes for a stable Sable release: roll up every beta, keep only the final state, check each claim against the code, and open a PR',
  whenToUse: 'When a stable release is ready for its notes. Args: {version: "1.5.1"}. Add ship: false to stop before the commit and PR.',
  phases: [
    { title: 'Gather', detail: 'the last stable tag, the betas since, and commits no notes cover' },
    { title: 'Extract', detail: 'every change in the beta notes and the uncovered commits' },
    { title: 'Reconcile', detail: 'one final-state list against the last stable release' },
    { title: 'Verify', detail: 'each area checked against the code, then a skeptic' },
    { title: 'Write', detail: 'the CHANGELOG section and the docs version' },
    { title: 'Check', detail: 'release checks, coverage, and a read as someone upgrading' },
    { title: 'Fix', detail: 'fixes and a recheck, two rounds at most' },
    { title: 'Ship', detail: 'two commits and a PR' },
  ],
}

// The notes compare the release with the stable release before it, never with
// its betas. Nick reviews the PR, and merging it is his go for the release, so
// this workflow never merges anything or starts a release.

const input = typeof args === 'string' ? { version: args } : (args || {})
const version = String(input.version || '').replace(/^v/, '')
if (!/^\d+\.\d+\.\d+$/.test(version)) return { status: 'blocked', blockers: ['Pass a stable version, like {version: "1.5.1"}.'] }
const ref = input.ref || 'origin/main'
const ship = input.ship !== false
const minor = version.endsWith('.0')

const text = { type: 'string' }
const texts = { type: 'array', items: text }
const KINDS = ['feature', 'improvement', 'fix', 'upgrade', 'configuration', 'internal']
const GATHER = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    blockers: texts,
    previous: { type: 'string', description: 'The newest stable version below this one, without the v' },
    head: { type: 'string', description: `Short hash of ${ref}` },
    today: { type: 'string', description: 'Today as YYYY-MM-DD' },
    betas: { type: 'array', items: text, description: 'Prerelease versions of this release with a CHANGELOG section, oldest first' },
    uncovered: { type: 'array', items: { type: 'object', properties: { hash: text, subject: text }, required: ['hash', 'subject'] } },
    commits: { type: 'integer', description: 'Commits since the previous stable tag' },
  },
  required: ['ok', 'blockers', 'previous', 'head', 'today', 'betas', 'uncovered', 'commits'],
}
const CHANGES = {
  type: 'object',
  properties: {
    changes: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'A short name for the thing, like "Hide Finding"' },
          area: { type: 'string', description: 'The ### heading it sits under, or the closest one' },
          kind: { type: 'string', enum: KINDS },
          detail: { type: 'string', description: 'What the source says it does, in one or two sentences' },
          source: { type: 'string', description: 'The beta version or commit hash it came from' },
        },
        required: ['title', 'area', 'kind', 'detail', 'source'],
      },
    },
  },
  required: ['changes'],
}
const RECONCILED = {
  type: 'object',
  properties: {
    entries: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'A short unique slug' },
          area: text,
          kind: { type: 'string', enum: KINDS },
          text: { type: 'string', description: 'One bullet in the voice of the notes' },
          claims: { type: 'array', items: text, description: 'Exact things a reader could check: UI names, menu paths, settings, defaults, limits, config keys' },
          sources: texts,
          headline: { type: 'boolean', description: 'One of the two or three changes the intro leads with' },
        },
        required: ['id', 'area', 'kind', 'text', 'claims', 'sources', 'headline'],
      },
    },
    dropped: { type: 'array', items: { type: 'object', properties: { title: text, reason: text }, required: ['title', 'reason'] } },
  },
  required: ['entries', 'dropped'],
}
const VERDICTS = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: text,
          verdict: { type: 'string', enum: ['confirmed', 'wrong', 'gone', 'unclear'] },
          evidence: { type: 'string', description: 'file:line, or a quote from the code' },
          correction: { type: 'string', description: 'For wrong, the bullet rewritten with the right facts; otherwise empty' },
        },
        required: ['id', 'verdict', 'evidence', 'correction'],
      },
    },
  },
  required: ['verdicts'],
}
const REFUTED = { type: 'object', properties: { results: { type: 'array', items: { type: 'object', properties: { id: text, refuted: { type: 'boolean' }, reason: text }, required: ['id', 'refuted', 'reason'] } } }, required: ['results'] }
const WRITTEN = { type: 'object', properties: { section: { type: 'string', description: 'The section exactly as written' }, docs: { type: 'array', items: text, description: 'Docs files changed' } }, required: ['section', 'docs'] }
const CHECKS = { type: 'object', properties: { ok: { type: 'boolean' }, failures: { type: 'array', items: { type: 'object', properties: { check: text, message: text }, required: ['check', 'message'] } } }, required: ['ok', 'failures'] }
const COVERAGE = { type: 'object', properties: { results: { type: 'array', items: { type: 'object', properties: { id: text, covered: { type: 'boolean' }, quote: text }, required: ['id', 'covered', 'quote'] } } }, required: ['results'] }
const READER = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: { where: { type: 'string', description: 'The bullet or heading' }, problem: text, suggestion: text, fix: { type: 'string', enum: ['mechanical', 'needs-nick'] } },
        required: ['where', 'problem', 'suggestion', 'fix'],
      },
    },
  },
  required: ['findings'],
}
const FIXED = {
  type: 'object',
  properties: {
    fixed: { type: 'array', items: { type: 'object', properties: { id: text, change: text }, required: ['id', 'change'] } },
    notFixed: { type: 'array', items: { type: 'object', properties: { id: text, reason: text }, required: ['id', 'reason'] } },
  },
  required: ['fixed', 'notFixed'],
}
const SHIPPED = { type: 'object', properties: { pr: text, commits: texts }, required: ['pr', 'commits'] }

phase('Gather')
const gather = await agent(`Get ready to write the notes for Sable ${version}. The current directory is a checkout of drudge/sable. Use shell commands and change nothing.

1. Run \`git fetch --tags origin\`. This checkout must be clean, and HEAD must contain ${ref} (\`git merge-base --is-ancestor ${ref} HEAD\`). If not, add the blocker "Sync this checkout with ${ref} first."
2. If CHANGELOG.md already has a "## [${version}]" section, add the blocker "CHANGELOG.md already has ${version} notes."
3. previous is the newest stable tag (vX.Y.Z, no suffix) below ${version} that ${ref} contains, without the v.
4. betas are the prerelease versions of ${version} that have a CHANGELOG.md section ("## [${version}-beta.N]" or "-rc.N"), oldest first.
5. uncovered is every non-merge commit that no notes describe yet: the ones after the commit that added the newest beta's section (find it with \`git log -S\`), or after v<previous> when there are no betas. Give each short hash and subject, and leave out commits that only touch release notes.
6. commits is how many commits v<previous>..${ref} has. head is \`git rev-parse --short=12 ${ref}\`. today is \`date +%F\`.
ok is true only when there are no blockers.`, { label: 'gather', phase: 'Gather', schema: GATHER, effort: 'low' })
if (!gather || !gather.ok) return { status: 'blocked', blockers: gather ? gather.blockers : ['The gather step did not finish.'] }
const previous = gather.previous.replace(/^v/, '')
const upgradingFrom = minor ? previous.split('.').slice(0, 2).join('.') : previous
const date = input.date || gather.today
log(`${gather.betas.length} beta(s), ${gather.uncovered.length} uncovered commit(s), and ${gather.commits} commits since ${previous}.`)

// Oldest first, so the reconcile step knows which description came last.
const sources = []
for (let index = 0; index < gather.betas.length; index += 4) sources.push({ betas: gather.betas.slice(index, index + 4) })
for (let index = 0; index < gather.uncovered.length; index += 25) sources.push({ commits: gather.uncovered.slice(index, index + 25) })
if (!sources.length) return { status: 'blocked', blockers: [`Nothing has changed since ${previous}.`] }
const describe = source => source.betas ? `the notes for ${source.betas.join(', ')}` : `${source.commits.length} uncovered commit(s)`

phase('Extract')
const extracted = await parallel(sources.map(source => () => source.betas
  ? agent(`Read these sections of CHANGELOG.md in this checkout: ${source.betas.map(beta => `"## [${beta}]"`).join(', ')}. List every change they describe, one entry per change. Beta notes can compare with earlier betas ("Upgrading from beta.12", "used to", "now"); record that as written, because a later step works out the final state. Keep UI names in **bold** and config keys in backticks. source is the beta version the change came from.`, { label: `notes ${source.betas[0]}${source.betas.length > 1 ? ' to ' + source.betas.at(-1) : ''}`, phase: 'Extract', schema: CHANGES, effort: 'low' })
  : agent(`No release notes describe these commits yet:
${source.commits.map(commit => `- ${commit.hash} ${commit.subject}`).join('\n')}

Read each one (\`git show --stat\`, then the diff where you need it) and list the changes a user would notice, one entry each. Skip refactors, tests, CI, and docs-only changes unless a user would notice them. Keep UI names in **bold** and config keys in backticks. source is the short hash.`, { label: `commits ${source.commits[0].hash}`, phase: 'Extract', schema: CHANGES })))
const unfinished = []
const changes = []
extracted.forEach((result, index) => {
  if (result) changes.push(...result.changes)
  else unfinished.push(`Couldn't read ${describe(sources[index])}, so those changes may be missing.`)
})
log(`${changes.length} change(s) found.`)

phase('Reconcile')
const reconciled = await agent(`These are the changes described since Sable ${previous}, oldest first: ${sources.map(describe).join(', then ')}. Turn them into the final list for the ${version} notes, which compare ${version} with ${previous} only.

- Merge entries about the same thing into one, described the way it works at the end. A rename, a moved setting, or a changed default shows up only in its final form.
- Drop anything added and then removed before ${version}, and fixes to bugs that only ever existed in a beta, since people on ${previous} never saw them. When the notes don't settle it, check the code in this checkout.
- Keep upgrade notes only when they matter to someone coming from ${previous}: a changed default, a moved setting or menu, a config migration, new background work, or something that now starts off.
- Leave out internal changes.
- Put each entry in an area. Reuse the ### headings of the notes for ${previous} and the stable release before it where they fit, and use Fixes and Configuration for those kinds.
- Write each entry's text as one bullet in the voice of those notes: it starts with a verb, keeps UI names in **bold** and config keys in backticks, and says what the user gets.
- claims are the exact things a reader could check: UI names and menu paths, setting names, defaults, limits, and config keys.
- Mark as headline the two or three changes the intro should lead with.
Return every dropped change with the reason.

Changes:
${JSON.stringify(changes)}`, { label: 'reconcile', phase: 'Reconcile', schema: RECONCILED })
if (!reconciled) return { status: 'needs-attention', stoppedAt: 'reconcile', unfinished: [...unfinished, 'The reconcile step did not finish.'] }
log(`${reconciled.entries.length} entries for the notes, ${reconciled.dropped.length} dropped.`)

phase('Verify')
// Each area gets one checker; small areas share one so a release with many
// one-line areas stays cheap.
const byArea = new Map()
for (const entry of reconciled.entries) {
  const key = entry.area.trim().toLowerCase()
  if (!byArea.has(key)) byArea.set(key, [])
  byArea.get(key).push(entry)
}
const batches = []
let pool = []
for (const group of [...byArea.values()].sort((a, b) => b.length - a.length)) {
  if (group.length >= 3) batches.push(group)
  else pool.push(...group)
  if (pool.length >= 8) {
    batches.push(pool)
    pool = []
  }
}
if (pool.length) batches.push(pool)
const areaNames = batch => [...new Set(batch.map(entry => entry.area))].join(', ')
const checked = await pipeline(batches,
  batch => agent(`Check these entries for the Sable ${version} notes against the code in this checkout, which contains ${ref} (${gather.head}). For every claim, find what proves it: UI text in the .templ files under internal/web, settings and defaults in internal/config, config keys in config.example.toml and docs/configuration.md, and limits in the code that enforces them.

The verdict for each entry is confirmed when every claim holds (cite file:line), wrong when a claim is off (rewrite the bullet with the right facts as correction), gone when the thing isn't in the code anymore, or unclear when you couldn't find it.

Entries:
${JSON.stringify(batch.map(({ id, text, claims }) => ({ id, text, claims })), null, 1)}`, { label: `verify ${areaNames(batch)}`, phase: 'Verify', schema: VERDICTS }),
  async (result, batch) => {
    if (!result) return { batch, verdicts: null, refuted: null }
    const confirmed = result.verdicts.filter(verdict => verdict.verdict === 'confirmed')
    if (!confirmed.length) return { batch, verdicts: result.verdicts, refuted: [] }
    const entries = confirmed.map(verdict => ({ ...batch.find(entry => entry.id === verdict.id), evidence: verdict.evidence }))
    const skeptic = await agent(`A checker confirmed these entries for the Sable ${version} notes. Try to prove each one wrong against the code in this checkout: the exact UI wording and capitalization, menu paths, defaults, limits, and whether it really behaves the way the bullet says. If you can't confirm every claim yourself, say refuted.

Entries with the checker's evidence:
${JSON.stringify(entries.map(({ id, text, claims, evidence }) => ({ id, text, claims, evidence })), null, 1)}`, { label: `skeptic ${areaNames(batch)}`, phase: 'Verify', schema: REFUTED })
    return { batch, verdicts: result.verdicts, refuted: skeptic ? skeptic.results.filter(item => item.refuted) : null }
  })

const final = []
const corrected = []
const leftOut = reconciled.dropped.map(item => ({ ...item, step: 'reconcile' }))
const needsNick = []
const doubts = []
for (const [index, item] of checked.entries()) {
  const batch = item ? item.batch : batches[index]
  if (!item || !item.verdicts) {
    unfinished.push(`The check for ${areaNames(batch)} did not finish, so those entries are unverified.`)
    final.push(...batch)
    continue
  }
  if (item.refuted === null) unfinished.push(`The skeptic for ${areaNames(batch)} did not finish.`)
  const verdicts = new Map(item.verdicts.map(verdict => [verdict.id, verdict]))
  const refuted = new Map((item.refuted || []).map(result => [result.id, result.reason]))
  for (const entry of batch) {
    const verdict = verdicts.get(entry.id)
    if (verdict && verdict.verdict === 'gone') {
      leftOut.push({ title: entry.text, reason: `Not in the code at ${gather.head}: ${verdict.evidence}`, step: 'verify' })
    } else if (verdict && verdict.verdict === 'wrong') {
      corrected.push({ id: entry.id, before: entry.text, after: verdict.correction, evidence: verdict.evidence })
      final.push({ ...entry, text: verdict.correction })
    } else {
      final.push(entry)
      if (!verdict || verdict.verdict === 'unclear') needsNick.push({ where: entry.text, problem: 'Couldn\'t confirm this against the code.', evidence: verdict ? verdict.evidence : 'No verdict came back.' })
      else if (refuted.has(entry.id)) doubts.push({ area: 'facts', where: entry.text, problem: `A skeptic doubts it: ${refuted.get(entry.id)}`, suggestion: 'Check the code, then fix the bullet or drop the claim you can\'t confirm.' })
    }
  }
}
log(`${final.length} entries kept: ${corrected.length} corrected, ${leftOut.length - reconciled.dropped.length} gone, ${doubts.length} doubted, ${needsNick.length} unconfirmed.`)

phase('Write')
const written = await agent(`Write the Sable ${version} section of CHANGELOG.md in this checkout as "## [${version}] - ${date}", directly above the newest section.

- Match the shape and voice of the most recent stable ${minor ? '.0 release, such as 1.5.0' : 'patch release'} in the file: a short intro that leads with ${final.filter(entry => entry.headline).map(entry => entry.id).join(', ') || 'the biggest changes'}, then "### Upgrading from ${upgradingFrom}" if there are upgrade notes, then one ### section per area with the biggest first, and Console, Fixes, and Configuration last.
- Use these entries and nothing else. You may tighten the wording, merge two bullets that say the same thing, and order them, but keep every fact.
- Compare only with ${previous}. Never mention betas, commits, or pull requests.
- Wrap lines at 80 characters like the rest of the file.

Then move the docs to ${version}: "version" and "versionLabel" in docs/navigation.json, every "covers Sable X" note, and the download link in docs/index.md. Leave "captured from Sable X" alone; it changes when the screenshots are retaken.

Don't commit. Return the section exactly as written.

Entries:
${JSON.stringify(final.map(({ id, area, kind, text, headline }) => ({ id, area, kind, text, headline })), null, 1)}`, { label: 'write', phase: 'Write', schema: WRITTEN })
if (!written) return { status: 'needs-attention', stoppedAt: 'write', unfinished: [...unfinished, 'The write step did not finish.'], leftOut, corrected, needsNick }

const checksPrompt = `In this checkout, run \`bash scripts/release-notes.sh v${version}\`, \`go tool mage validateReleaseVersion ${version}\`, and \`GOEXPERIMENT=jsonv2 go test -count=1 ./docs/\`. Report each failure with its output. Don't change files.`
const coveragePrompt = entries => `Read the "## [${version}]" section of CHANGELOG.md in this checkout. For each entry below, say whether a bullet there covers it, quoting that bullet, or that nothing does. Don't change files.

Entries:
${JSON.stringify(entries.map(({ id, text }) => ({ id, text })), null, 1)}`
const checkFindings = result => (result?.failures || []).map(failure => ({ area: 'checks', where: failure.check, problem: 'A release check fails.', evidence: failure.message, suggestion: 'Fix the cause.' }))
const coverageFindings = (result, entries) => (result?.results || []).filter(item => !item.covered).map(item => {
  const entry = entries.find(candidate => candidate.id === item.id)
  return { area: 'coverage', where: item.id, problem: 'No bullet covers this entry.', evidence: entry ? entry.text : item.id, suggestion: 'Add it where it fits, or fold it into the bullet it belongs with.' }
})

phase('Check')
const [checks, coverage, reader] = await parallel([
  () => agent(checksPrompt, { label: 'release checks', phase: 'Check', schema: CHECKS, effort: 'low' }),
  () => agent(coveragePrompt(final), { label: 'coverage', phase: 'Check', schema: COVERAGE }),
  () => agent(`Read the "## [${version}]" section of CHANGELOG.md in this checkout as someone about to upgrade from ${previous}. List anything that would trip them up: jargon or internal names, a bullet about what changed in the code instead of what they get, anything that assumes they ran a beta, or an upgrade surprise with no warning under "Upgrading from ${upgradingFrom}". Rewording and a missing warning are mechanical. Leaving something out or changing what the release leads with is needs-nick. Don't change files.`, { label: 'read as an upgrader', phase: 'Check', schema: READER }),
])
for (const [name, result] of [['release checks', checks], ['coverage check', coverage], ['upgrader read', reader]]) if (!result) unfinished.push(`The ${name} did not finish.`)
for (const finding of reader?.findings || []) if (finding.fix === 'needs-nick') needsNick.push({ where: finding.where, problem: finding.problem, evidence: finding.suggestion })
const findings = [...checkFindings(checks), ...coverageFindings(coverage, final), ...(reader?.findings || []).filter(finding => finding.fix === 'mechanical').map(finding => ({ area: 'wording', where: finding.where, problem: finding.problem, evidence: '', suggestion: finding.suggestion })), ...doubts]
log(`${findings.length} thing(s) to fix, ${needsNick.length} for Nick.`)

phase('Fix')
// remaining is what is still broken after the latest round. Anything the fixer
// declines goes to Nick instead, unless it is a failing check, which stays
// broken until something fixes it.
let remaining = findings
let lastChecks = checks
const fixed = []
const declined = new Set()
for (let round = 1; round <= 2 && remaining.length; round++) {
  const numbered = remaining.map((finding, index) => ({ id: `p${index + 1}`, ...finding }))
  const result = await agent(`Fix these problems in the Sable ${version} notes in CHANGELOG.md, and in docs/ if a check points there. Make the smallest change that fixes each one, keep the voice of the notes, and keep comparing only with ${previous}. For a doubted fact, check the code: fix the bullet if it is wrong, and drop only the claim you can't confirm. Don't commit. If a fix would change what the notes lead with or leave out, don't make it; list it under notFixed with the reason. Answer with each problem's id.

Problems:
${JSON.stringify(numbered, null, 1)}`, { label: `fix round ${round}`, phase: 'Fix', schema: FIXED })
  if (!result) {
    unfinished.push(`Fix round ${round} did not finish.`)
    break
  }
  const fixedIds = new Set(result.fixed.map(item => item.id))
  const declinedIds = new Set(result.notFixed.map(item => item.id))
  for (const item of result.fixed) fixed.push({ ...item, where: numbered.find(finding => finding.id === item.id)?.where || item.id })
  for (const item of result.notFixed) {
    const finding = numbered.find(candidate => candidate.id === item.id)
    if (finding) declined.add(finding.where)
    needsNick.push({ where: finding ? finding.where : item.id, problem: 'The fixer left this for you.', evidence: item.reason })
  }
  const [rechecks, recoverage] = await parallel([
    () => agent(checksPrompt, { label: `release checks ${round}`, phase: 'Fix', schema: CHECKS, effort: 'low' }),
    async () => numbered.some(finding => finding.area === 'coverage') ? agent(coveragePrompt(final), { label: `coverage ${round}`, phase: 'Fix', schema: COVERAGE }) : null,
  ])
  lastChecks = rechecks
  // Checks and coverage are measured again. Wording and doubted facts have no
  // recheck, so they stay unless the fixer handled or declined them, and so
  // does anything whose recheck didn't finish.
  const carried = numbered.filter(finding => {
    if (finding.area === 'checks') return !rechecks
    if (finding.area === 'coverage') return !recoverage && !declinedIds.has(finding.id)
    return !fixedIds.has(finding.id) && !declinedIds.has(finding.id)
  }).map(({ id, ...finding }) => finding)
  remaining = [...checkFindings(rechecks), ...(recoverage ? coverageFindings(recoverage, final).filter(finding => !declined.has(finding.where)) : []), ...carried]
  log(remaining.length ? `Round ${round} left ${remaining.length} problem(s).` : `Round ${round} fixed everything.`)
}
const ready = !remaining.length && !unfinished.length && Boolean(lastChecks?.ok)

let shipped = null
if (ship) {
  phase('Ship')
  shipped = await agent(`Ship the Sable ${version} release notes as a pull request. Never merge it and never start the release; Nick's merge is the go.

1. If the current branch is main, create claude/release-notes-v${version}; otherwise stay on the current branch.
2. Commit CHANGELOG.md as "Add ${version} release notes", then the docs/ changes as "docs: name ${version} as the current release". Skip a commit that would be empty.
3. Push with -u and open a PR on drudge/sable against main titled "Add ${version} release notes"${ready ? '' : ', as a draft, because something below is unresolved'}. In a few short lines the body says what the notes lead with, what they fold together from the betas, what was left out and why, which facts were corrected against the code, and what still needs Nick.

Left out: ${JSON.stringify(leftOut.map(item => `${item.title}: ${item.reason}`))}
Corrected against the code: ${JSON.stringify(corrected.map(item => item.after))}
Still needs Nick: ${JSON.stringify(needsNick.map(item => `${item.where}: ${item.problem}`))}
Still broken: ${JSON.stringify(remaining.map(item => `${item.where}: ${item.problem}`))}
Didn't finish: ${JSON.stringify(unfinished)}

Return the PR URL and the commit subjects.`, { label: 'commit and PR', phase: 'Ship', schema: SHIPPED })
  if (!shipped) unfinished.push('The ship step did not finish.')
}

const byAreaCount = {}
for (const entry of final) byAreaCount[entry.area] = (byAreaCount[entry.area] || 0) + 1
return {
  status: ready && (shipped || !ship) ? 'ready' : 'needs-attention',
  version,
  previous,
  pr: shipped ? shipped.pr : (ship ? 'The ship step did not finish.' : 'Not shipped (ship: false). The notes are written in this checkout.'),
  commits: shipped ? shipped.commits : [],
  lead: final.filter(entry => entry.headline).map(entry => entry.text),
  byArea: byAreaCount,
  sources: { betas: gather.betas, uncoveredCommits: gather.uncovered.length, commitsSincePrevious: gather.commits },
  leftOut,
  corrected,
  fixed,
  needsNick,
  stillBroken: remaining,
  unfinished,
  section: written.section,
}
