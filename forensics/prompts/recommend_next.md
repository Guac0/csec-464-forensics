<!--
The question sent when an analyst clicks "What should I run next?". The AI sees the
investigation state: runs so far, hook findings, flagged rows and the guide's recommendations.
The app adds the analyst's focus (if any) and its fixed rules (no repeats, end with the
suggestions block) after this text.
EXAMPLE - TODO(forensics): refine.
-->
Recommend what the analyst should run next on this image: 1 to 5 volatility queries, given the
investigation state in the context.
- Start with 2-4 sentences: the current stage of the investigation and why these queries are
  the most useful next steps.
- Prefer specific options grounded in the data (e.g. the "pid" of a flagged process) over
  plain runs when that narrows the output usefully.
