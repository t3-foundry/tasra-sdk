// VERIFY · consolidated report. Aggregates every stage's StepResult into a
// human-readable markdown report and a machine-readable JSON, both under
// test/verify/out/. The run is GREEN only if no required step failed.

import {mkdirSync, writeFileSync} from 'node:fs'
import {resolve} from 'node:path'
import {outDir, type Metric, type StepResult} from './_run.ts'

export interface ReportMeta {
  startedAt: string
  finishedAt: string
  totalMs: number
  config: Record<string, string>
}

const ICON: Record<string, string> = {pass: '✅', fail: '❌', skip: '⚠️'}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m${Math.round((ms % 60_000) / 1000)}s`
}

function metricLine(m: Metric): string {
  const extra = Object.entries(m)
    .filter(([k]) => !['name', 'value', 'unit'].includes(k))
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
  return `${m.name}: **${m.value}**${m.unit ? ` ${m.unit}` : ''}${extra ? ` (${extra})` : ''}`
}

export function buildMarkdown(results: StepResult[], meta: ReportMeta): string {
  const phases = [...new Set(results.map(r => r.phase))]
  const pass = results.filter(r => r.status === 'pass').length
  const fail = results.filter(r => r.status === 'fail').length
  const skip = results.filter(r => r.status === 'skip').length
  const requiredFail = results.filter(r => r.status !== 'pass' && !r.optional).length

  const lines: string[] = []
  lines.push(`# Keykeeper stack verification report`)
  lines.push('')
  lines.push(`**${requiredFail === 0 ? '✅ PASS' : '❌ FAIL'}** — ${pass} passed, ${fail} failed, ${skip} skipped · ${fmtMs(meta.totalMs)} · ${meta.finishedAt}`)
  lines.push('')
  lines.push('Production services on the configured chain, with a threshold accountant set, holder-bound verifier flow, and explorer.')
  lines.push('')

  // config
  lines.push('## Configuration')
  lines.push('')
  lines.push('| key | value |')
  lines.push('| --- | --- |')
  for (const [k, v] of Object.entries(meta.config)) lines.push(`| ${k} | ${v} |`)
  lines.push('')

  // summary table
  lines.push('## Summary')
  lines.push('')
  lines.push('| phase | step | result | time | key metrics |')
  lines.push('| --- | --- | --- | --- | --- |')
  for (const r of results) {
    const km = r.metrics.length ? r.metrics.map(m => `${m.name}=${m.value}${m.unit ? m.unit : ''}`).join('; ') : ''
    lines.push(`| ${r.phase} | ${r.name} | ${ICON[r.status]} ${r.status} | ${fmtMs(r.ms)} | ${km} |`)
  }
  lines.push('')

  // per-phase detail
  for (const phase of phases) {
    const rs = results.filter(r => r.phase === phase)
    lines.push(`## ${phase}`)
    lines.push('')
    for (const r of rs) {
      lines.push(`### ${ICON[r.status]} ${r.name} — ${r.status} (${fmtMs(r.ms)})`)
      if (r.metrics.length) {
        lines.push('')
        for (const m of r.metrics) lines.push(`- ${metricLine(m)}`)
      }
      if (r.detail && r.status !== 'pass') {
        lines.push('')
        lines.push('```')
        lines.push(r.detail.trim())
        lines.push('```')
      }
      lines.push('')
    }
  }
  return lines.join('\n')
}

export function writeReport(results: StepResult[], meta: ReportMeta): {anyRequiredFail: boolean; mdPath: string; jsonPath: string} {
  mkdirSync(outDir, {recursive: true})
  const md = buildMarkdown(results, meta)
  const mdPath = resolve(outDir, 'verify-report.md')
  const jsonPath = resolve(outDir, 'verify-report.json')
  writeFileSync(mdPath, md)
  const allMetrics = results.flatMap(r => r.metrics.map(m => ({phase: r.phase, step: r.name, ...m})))
  writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        ...meta,
        summary: {
          pass: results.filter(r => r.status === 'pass').length,
          fail: results.filter(r => r.status === 'fail').length,
          skip: results.filter(r => r.status === 'skip').length,
        },
        results,
        metrics: allMetrics,
      },
      null,
      2,
    ),
  )
  return {anyRequiredFail: results.some(r => r.status !== 'pass' && !r.optional), mdPath, jsonPath}
}
