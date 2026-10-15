# Troubleshooting

This page is short. The detailed symptom-to-cause guide is [docs/troubleshooting.md](docs/troubleshooting.md).

Start with:

```bash
ratriyx doctor --mode tor
```

Each failed line shows the next step. Exit code 1 means at least one check failed. Exit code 3 means the platform is not supported. Exit code 4 means a route was required but not verified, so nothing was launched. Exit code 5 means an approval is needed first.
