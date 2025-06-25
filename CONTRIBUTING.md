# Contributing to gcrypt

Thank you for your interest in contributing to gcrypt! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Contribution Guidelines](#contribution-guidelines)
- [Security Contributions](#security-contributions)
- [Legal Requirements](#legal-requirements)

## Code of Conduct

### Our Pledge

We are committed to providing a friendly, safe, and welcoming environment for all contributors, regardless of:
- Experience level
- Gender identity and expression
- Sexual orientation
- Disability
- Personal appearance
- Body size
- Race, ethnicity, or religion
- Nationality
- Age

### Expected Behavior

- Be respectful and considerate
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members
- Use welcoming and inclusive language

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Personal attacks or insults
- Trolling or deliberately inflammatory behavior
- Publishing others' private information
- Any conduct that could reasonably be considered inappropriate

### Enforcement

Violations should be reported to conduct@gcrypt.rs. All reports will be reviewed and investigated promptly and fairly.

## Getting Started

### Prerequisites

- Rust 1.85.0 or later
- Git
- Basic understanding of cryptography
- Familiarity with Rust programming

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/CK-Technology/gcrypt.git
cd gcrypt

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Development Tools

```bash
# Install development tools
cargo install cargo-audit    # Security vulnerability scanner
cargo install cargo-criterion # Benchmarking tool
cargo install cargo-expand   # Macro expansion viewer

# Run security audit
cargo audit

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings
```

## Development Process

### Branch Strategy

- `main` - Stable branch, always passing CI
- `develop` - Development branch for next release
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches
- `security/*` - Security fix branches (private)

### Workflow

1. **Fork** the repository
2. **Create** a feature branch from `develop`
3. **Commit** your changes with clear messages
4. **Test** thoroughly including new tests
5. **Push** to your fork
6. **Submit** a Pull Request to `develop`

### Commit Guidelines

Follow conventional commits format:

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions or modifications
- `build`: Build system changes
- `ci`: CI configuration changes
- `chore`: Other changes

Example:
```
feat(ed25519): add batch verification support

Implement batch verification for Ed25519 signatures using 
Straus's algorithm for improved performance.

Closes #123
```

## Contribution Guidelines

### Code Style

- Follow Rust standard style guidelines
- Use `cargo fmt` before committing
- Ensure `cargo clippy` passes with no warnings
- Add documentation for all public APIs
- Include examples in documentation

### Testing Requirements

- Write tests for all new functionality
- Maintain or improve code coverage
- Include both positive and negative test cases
- Add property-based tests where appropriate
- Ensure constant-time properties are preserved

### Documentation

- Document all public APIs with `///` comments
- Include examples in documentation
- Update README if adding features
- Add entries to CHANGELOG.md
- Update benchmarks if performance-relevant

### Performance Considerations

- Benchmark performance-critical changes
- Avoid allocations in hot paths
- Maintain constant-time properties
- Consider SIMD optimizations
- Profile before optimizing

## Security Contributions

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities. Instead:

1. Email security@gcrypt.rs with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

2. Use PGP encryption if possible (key available on request)

3. Allow up to 48 hours for initial response

### Security Fix Process

1. Report privately as above
2. Work with maintainers on fix
3. Coordinate disclosure timeline
4. Receive credit in security advisory

### Security Best Practices

When contributing:
- Ensure all operations are constant-time
- Clear sensitive data with `zeroize`
- Validate all inputs
- Consider side-channel attacks
- Document security properties

## Legal Requirements

### Contributor License Agreement

By contributing, you agree that:

1. **Copyright**: You own the copyright to your contribution or have permission to submit it

2. **License Grant**: You grant gcrypt a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable license to use your contribution

3. **Patent Grant**: You grant a patent license for any patents that would be infringed by your contribution

4. **Original Work**: Your contribution is your original work or you have the right to submit it

### Sign-Off Requirement

Add a sign-off to your commits:

```bash
git commit -s -m "Your commit message"
```

This adds `Signed-off-by: Your Name <your@email.com>` to the commit.

### License Headers

For new files, add:

```rust
// Copyright 2024 The gcrypt Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
```

## Review Process

### Pull Request Checklist

Before submitting:
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Benchmarks run (if applicable)
- [ ] Security implications considered
- [ ] Commits are signed-off
- [ ] PR description is clear

### Review Criteria

PRs are reviewed for:
- Correctness and security
- Code quality and style
- Test coverage
- Documentation completeness
- Performance impact
- API design (for new features)
- Backward compatibility

### Merge Requirements

- All CI checks pass
- At least one maintainer approval
- No unresolved review comments
- Rebased on latest `develop`
- Commits squashed if requested

## Recognition

### Contributors

All contributors are recognized in:
- Git history
- CONTRIBUTORS.md file
- Release notes (for significant contributions)

### Security Acknowledgments

Security researchers are acknowledged in:
- Security advisories
- SECURITY.md hall of fame
- Release notes

## Questions and Support

### Getting Help

- GitHub Discussions for questions
- Issue tracker for bugs
- Security email for vulnerabilities
- Matrix/Discord for real-time chat

### Maintainer Contacts

- General: maintainers@gcrypt.rs
- Security: security@gcrypt.rs
- Legal: legal@gcrypt.rs

## Resources

### Learning Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cryptography Engineering](https://www.schneier.com/books/cryptography-engineering/)
- [A Graduate Course in Applied Cryptography](http://toc.cryptobook.us/)
- [The Joy of Cryptography](https://joyofcryptography.com/)

### Development Resources

- [API Documentation](https://docs.rs/gcrypt)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Security Model](SECURITY.md)
- [Performance Guide](docs/performance.md)

Thank you for contributing to gcrypt! Your efforts help make cryptography more accessible and secure for everyone.