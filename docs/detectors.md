# Detector Development

A detector should:

- have a stable name;
- return a severity and confidence;
- minimize false positives;
- redact sensitive material in output;
- include focused tests;
- never contact the detected service as part of normal scanning.

Provider-specific detectors should live independently so they can be enabled, tested and evolved without changing the scanner engine.
