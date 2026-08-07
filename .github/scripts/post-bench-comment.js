// Post or update the benchmark results comment on a PR.
// Reads the verdict from target/bench/workdir/compare.json.
module.exports = async ({ github, context }) => {
  const fs = require('fs');
  const verdict = JSON.parse(fs.readFileSync('target/bench/workdir/compare.json', 'utf8'));
  const { owner, repo, number } = context.issue;
  const marker = '<!-- binwalk-bench-comment -->';
  let body = marker + '\n\n## Benchmark results\n\n';
  if (verdict.base_sha) body += `_vs baseline from \`${verdict.base_sha}\`_\n\n`;
  body += verdict.md + '\n';
  if (verdict.regressed) body += '\n**Regressions detected**\n';
  if (verdict.warnings && verdict.warnings.length) {
    body += verdict.warnings.map(w => `- ${w}`).join('\n') + '\n';
  }
  const comments = await github.rest.issues.listComments({ owner, repo, issue_number: number });
  const existing = comments.data.find(c => c.body && c.body.includes(marker));
  if (existing) {
    await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
  } else {
    await github.rest.issues.createComment({ owner, repo, issue_number: number, body });
  }
};
