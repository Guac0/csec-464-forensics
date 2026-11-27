# Evidence export: sample\.raw

## Summary

|  |  |
|---|---|
| Generated (UTC) | <TIME> |
| Scope | sample\.raw |
| Evidence items | 1 |
| Runs | 1 |
| Application version | <VERSION> |
| Tool versions | 2\.28\.2 |
| AI prompt version (current) | `placeholder-1` |
| Integrity mode | `strict` |
| Audit log | verified, 16 events, head #16 `<HEAD>` |

## Contents

- Evidence 2: sample\.raw
- Leads from linked evidence
- Activity log

## Evidence 2: sample\.raw

|  |  |
|---|---|
| File | `sample.raw` |
| Size | 4.0 KiB (4096 bytes) |
| Registered | <TIME> |
| Description | Laptop \<script\>alert\(1\)\</script\> \| \`tick\` \`\`\` \*bold\* \[link\]\(http://x\) \# head |
| OS info | — |
| Integrity | **mismatch** — sample\.raw does not match its expected MD5\. Correct the expected hashes or acknowledge the mismatch on the evidence page\. |
| Last hashed | <TIME> |

**Hashes**

| Algorithm | Computed | Expected (acquisition) | Match |
|---|---|---|---|
| SHA-256 | `ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7` | — | — |
| MD5 | `620f0b67a91f7f74151bc5be745b7110` | `00000000000000000000000000000000` | **NO** |
| SHA-1 | `1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d` | — | — |

**Integrity history**

| When (UTC) | Kind | Result | SHA-256 | Run | Detail |
|---|---|---|---|---|---|
| <TIME> | initial | ok | `ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7` | — | — |

### Notes on sample\.raw

Note 1 (<TIME>):

````text
Analyst note <script>alert(1)</script> | `tick` ``` *bold* [link](http://x) # head
````

### Runs on sample\.raw

| Run | Plugin | Args | Origin | Status | Rows | Finished (UTC) |
|---|---|---|---|---|---|---|
| 1 | `windows.pslist.PsList` | `{"pid": [4]}` | manual | succeeded | 2 | — |

#### Run 1: windows\.pslist\.PsList

|  |  |
|---|---|
| Status | succeeded |
| Tool | volatility3 2\.28\.2 |
| Evidence at run time | SHA-256 `ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7`, 4.0 KiB (4096 bytes) |
| Raw output SHA-256 | `78378461cd04eab1c3380e68efef274fd9a9eef73e69c85e8c6ed140ec691f77` |
| Started / finished (UTC) | — / — |
| Rows | 2 |

Exact command:

```sh
vol -f /evidence/sample.raw windows.pslist.PsList --pid 4
```

Automated findings (post-run hooks; heuristics to verify):

- **high** Odd \<script\>alert\(1\)\</script\> \| \`tick\` \`\`\` \*bold\* \[link\]\(http://x\) \# head — d (rows R1:1) _(hook h)_

Dumped files (may be malware):

| File | Type | Size | SHA-256 | MD5 | SHA-1 | Row |
|---|---|---|---|---|---|---|
| `pid.4.dmp` | MZ executable | 10 bytes | `c79403462245656b62f9f0c4b88a989ce72558b52ab7e581572de2a9b67e7785` | `cf7b1680a65d4136c084af0ad4aed723` | `b97b3203cb65809f697e3356013cf134a27c3434` | R1:0 |

### AI analysis of sample\.raw

#### AI answer 2 (<TIME>)

> **AI\-generated lead — not evidence\. Verify against the cited rows\.**

Question:

````text
What stands out? <script>alert(1)</script> | `tick` ``` *bold* [link](http://x) # head
````

Answer:

````text
PID 666 [R1:1] and [R1:99]. <script>alert(1)</script> | `tick` ``` *bold* [link](http://x) # head
````

|  |  |
|---|---|
| Model (requested / returned) | `test-model` / `test-model` |
| Prompt version | `placeholder-1` |
| Parameters | `{"max_tokens": 2000, "model": "test-model", "temperature": 0.2}` |
| Provider | `<PROVIDER>` |
| Citations | 2 (1 invalid: R1:99) |
| Prompt SHA-256 | `<PROMPT-SHA256>` |
| Usage | `{"total_tokens": 42}` |

## Leads from linked evidence

Shared by an analyst from other images in the cases sample\.raw belongs to. They are NOT findings on this image: each points to its source image.

### Case 1: Intrusion (this image: before)

#### Note: Note 2

|  |  |
|---|---|
| From | other\.raw (after \<script\>alert\(1\)\</script\> \| \`tick\` \`\`\` \*bold\* \[link\]\(http://x\) \# head) |
| Source | `N2` |
| Shared | <TIME> by local |
| State | current |
| Comment | see \<script\>alert\(1\)\</script\> \| \`tick\` \`\`\` \*bold\* \[link\]\(http://x\) \# head |

```text
Note on the other image
```

## Activity log

Changes and key reads for this evidence; page and API requests are not included. Event numbers are the audit log's sequence numbers (gaps here are other evidence or requests, not deletions).

| # | Time (UTC) | Origin | Category | Action | Summary |
|---|---|---|---|---|---|
| 2 | <TIME> | system | change | `evidence.register` | Registered evidence sample\.raw |
| 4 | <TIME> | system | change | `evidence.describe` | Changed description of sample\.raw |
| 5 | <TIME> | system | change | `evidence.hash` | Hashed sample\.raw \(initial\): ok |
| 6 | <TIME> | system | change | `evidence.expected_hashes` | Expected hashes for sample\.raw set; status mismatch |
| 7 | <TIME> | system | change | `note.create` | Note 1 created \(version 1\) |
| 10 | <TIME> | system | change | `case.add_evidence` | Added sample\.raw to case Intrusion |
| 14 | <TIME> | system | change | `ai.ask.request` | AI question asked |
| 15 | <TIME> | system | change | `ai.ask.response` | AI responded \(test\-model\) |
| 16 | <TIME> | system | change | `share.create` | Shared result row R1:1 to case Intrusion |

## About this report

- Tool output tables are not reproduced here; each run lists its exact command, the SHA-256 of the evidence it ran against and of its raw output. The ZIP bundle contains every run's rows (CSV) and raw output, with a manifest of SHA-256 hashes.
- Sections marked “AI\-generated lead — not evidence\. Verify against the cited rows\.” were written by an AI model and are leads for an analyst, not findings.
- Text taken from evidence is escaped or shown in code blocks exactly as recovered.
