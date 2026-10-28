# Windows download link tool

A small, standalone uqitong tool for checking Microsoft's public Windows ISO
download service. It validates an exact media filename and size with a one-byte
HTTP Range request. It does not download or host ISO images, alter Windows,
publish websites, or require production credentials.

## Scope

- Uses only Microsoft's public download flow. No proxies, CAPTCHA solving,
  credential collection, IP rotation, or retry after an explicit rejection.
- A rejected or removed product is reported as unavailable, never substituted
  with a different image or evaluation edition.
- The example target manifest contains public product and media identifiers,
  not signed URLs or private website source.
- The workflow checks twice daily at 05:23 and 17:23 UTC (13:23 and 01:23 in
  Asia/Shanghai). Manual checks remain available. Each run uses one standard
  Ubuntu runner with a 15-minute timeout and read-only repository permission.
- No custom runner, paid service, ISO cache, or production upload is configured.

## Local use

Requires Node.js 22.13 or later, with no third-party runtime dependencies.

```sh
npm test
node cli.mjs keygen private/recipient.pem private/recipient-public.pem
node cli.mjs acquire targets.json private/recipient-public.pem output/results.enc.json
node cli.mjs decrypt output/results.enc.json private/recipient.pem private/results.json
```

The private key and decrypted results must stay local and must never be committed.
For the GitHub workflow, set the repository variable
`RECIPIENT_PUBLIC_KEY` to the public PEM key. Only the public key is sent to the
runner. Results use a random AES-256-GCM key wrapped with RSA-OAEP-SHA256 and are
uploaded as an encrypted artifact retained for one day. Logs contain only IDs,
status codes, filenames, sizes, and expiration times, never signed URLs.

CI results use payload version 2 with the repository, workflow, ref, commit,
run ID, run attempt, raw manifest SHA-256 and selected target IDs inside the
encrypted payload. These fields are explicitly populated from GitHub workflow
context; missing or mixed context is rejected before making source requests.
Normal local acquisition keeps the version 1 payload without a CI source.
Artifacts are named `encrypted-download-results-<run-id>-<run-attempt>` so an
automatic consumer can bind a result to one invocation. Encryption alone does
not prove who produced a result: a consumer must independently verify the
GitHub repository, workflow, trusted commit, run/attempt, artifact metadata and
digest, then validate the exact media identity, expiry and one-byte Range.

The optional `target_ids` workflow input (or local `TARGET_IDS` environment
variable) selects an exact comma-separated subset of the checked-in manifest.
It cannot add URLs or arbitrary products. Use it to avoid requesting links that
are already healthy. Explicit rejections stop the current item's attempt;
there are no automatic request retries or runner/egress rotation.

Exit status is nonzero when any requested item fails. Verified partial results
are still encrypted so a consumer can recover individual downloads. A consumer
must independently validate the exact expected media identity, expiry and Range
response before using results. Range verification is not a whole-file hash check.

## Scheduling and availability limits

GitHub's standard hosted runners are free for public repositories under its
current policy; this workflow does not use larger or custom paid runners.
Scheduling does not guarantee availability. GitHub can delay or drop scheduled
jobs during high load and automatically disables schedules in a public
repository after 60 days without repository activity. An external consumer
should check workflow state and explicitly re-enable an inactivity-disabled
schedule when authorized; this project does not generate artificial keepalive
commits. Microsoft can also reject a request or withdraw media. A scheduled
run makes one attempt per selected item, with no automatic retry after an
explicit rejection. Do not treat two daily attempts as a guarantee of 365-day
uninterrupted downloads, nor as a website-publishing service.

## Upstream references

- https://www.microsoft.com/zh-cn/software-download/windows11
- https://www.microsoft.com/zh-cn/software-download/windows11arm64
- https://docs.github.com/en/billing/concepts/product-billing/github-actions
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule

This project is not affiliated with Microsoft. Windows licensing is unchanged.
