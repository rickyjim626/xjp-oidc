# Contributing to xjp-oidc

Thank you for your interest in contributing to xjp-oidc! We welcome contributions from the community.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct: be respectful, inclusive, and constructive.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/xjp-oidc.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test --workspace --all-features`
6. Submit a pull request

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone the repository
git clone https://github.com/xiaojinpro/xjp-oidc.git
cd xjp-oidc

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace

# Run examples
cargo run --example axum-bff
```

## Pull Request Process

1. **Update documentation** - Update README.md and other docs with details of changes
2. **Add tests** - Ensure new functionality has appropriate test coverage
3. **Update CHANGELOG** - Note your changes in the unreleased section
4. **Pass CI** - Ensure all tests pass and there are no clippy warnings
5. **Request review** - Once ready, request review from maintainers

## Development Guidelines

### Code Style

- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes with no warnings
- Follow Rust naming conventions and idioms

### Testing

- Write unit tests for new functionality
- Add integration tests for API changes
- Ensure examples still compile and run

### Documentation

- Document all public APIs
- Include examples in doc comments
- Update user-facing documentation

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer(s)]
```

Types: feat, fix, docs, style, refactor, test, chore

Example:
```
feat(verify): add support for custom claim validation

- Add CustomClaimValidator trait
- Implement validators for common patterns
- Update documentation with examples

Closes #123
```

## Testing

### Running Tests

```bash
# All tests
cargo test --workspace --all-features

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

### WASM Testing

```bash
# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Test WASM build
cd xjp-oidc
wasm-pack test --headless --firefox
```

## Feature Development

### Adding a New Feature

1. Discuss the feature in an issue first
2. Add feature flag if optional
3. Implement with tests
4. Update documentation
5. Add example if applicable

### Feature Flags

```toml
[features]
my-feature = ["dep:some-crate"]
```

## Security

- Never commit secrets or credentials
- Be careful with error messages - don't leak sensitive info
- Follow OWASP guidelines for auth/crypto code
- Report security issues privately to security@example.com

## Release Process

Releases are managed by maintainers:

1. Update version in Cargo.toml files
2. Update CHANGELOG.md
3. Create git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
4. Push tag: `git push origin v1.0.0`
5. CI will automatically publish to crates.io

## Questions?

- Check existing issues and discussions
- Ask in GitHub Discussions
- Contact maintainers

Thank you for contributing!