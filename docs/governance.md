# repository governance

status: applies to the `main` branch during the single-maintainer research phase

## normal change path

all `main` changes use a pull request. the branch ruleset requires:

- `quality / mock`;
- `build / sp1`;
- `build / risc0`;
- an up-to-date branch;
- resolved review conversations;
- squash merge.

force pushes and branch deletion are blocked. real-backend proof evidence is scheduled, manually dispatchable, and available on pull requests through the `backend-evidence` label, but is not a required check because proving latency is high.

## review policy

Veil currently has one maintainer. requiring an approval or code-owner review would either deadlock every pull request or encourage meaningless self-approval, so the ruleset requires zero approvals. focused external review is still requested for cryptography, consensus, serialization, and trust-boundary changes.

Copilot auto-review may comment on pull requests. it is advisory and is not a required approval or status check.

revisit the approval policy when a second active maintainer can review changes. do not add a review requirement before assigning an actual reviewer.

## administrator bypass

repository administrators retain ruleset bypass solely for emergencies:

- revoking compromised credentials or artifacts;
- disabling an actively exploitable path;
- repairing a confirmed GitHub Actions/platform outage that blocks all pull requests.

bypass is not the normal merge path. any use must be followed by a public issue or pull-request comment stating:

1. why the normal required-check path was unavailable or unsafe;
2. the exact commit pushed;
3. verification performed;
4. the follow-up change restoring normal enforcement.

research deadlines, slow proof jobs, failing tests, and missing reviews are not emergencies.
