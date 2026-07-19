# Contributing to crypto-secure

First off, thanks for taking the time to contribute! 🎉

## Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before submitting a bug report, please check the [existing issues](https://github.com/Vineet1576/crypto-secure/issues) to see if the problem has already been reported. If it hasn't, [open a new issue](https://github.com/Vineet1576/crypto-secure/issues/new) and include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (Node.js version, OS, browser if client-side)
- A minimal code reproduction if possible

### Suggesting Features

Open an [issue](https://github.com/Vineet1576/crypto-secure/issues/new) describing:

- The problem you're trying to solve
- How the feature would work
- Any alternatives you've considered

### Pull Requests

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Commit** your changes with clear, descriptive messages
4. **Push** to your fork and submit a pull request
5. **Wait for review** — we'll respond as soon as possible

#### Pull Request Guidelines

- Keep changes focused — one feature/fix per PR
- Update documentation (README, JSDoc comments) if your change affects the API
- Ensure backward compatibility unless it's a breaking change (in which case, note it clearly)
- Test your changes thoroughly
- Follow the existing code style (no linter config yet — match surrounding code)

## Development Setup

```bash
git clone https://github.com/Vineet1576/crypto-secure.git
cd crypto-secure
npm install
```

The package has no build step — all files are plain JavaScript.

### Project Structure

```
crypto-secure/
├── index.js              # Package entry (CommonJS)
├── crypto-secure.js      # Core crypto engine (UMD) — ECDH + RSA
├── middleware.js          # Express middleware (CommonJS)
├── client.js             # Node.js client (CommonJS)
├── client-browser.mjs    # Browser client (ES Module)
├── package.json
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── LICENSE
```

### Testing

Currently no automated test suite is configured.

```bash
npm test
```

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, contact the maintainers privately via the repository's security advisory feature.

## Questions?

Feel free to open a [discussion](https://github.com/Vineet1576/crypto-secure/discussions) or ask in the issue tracker.
