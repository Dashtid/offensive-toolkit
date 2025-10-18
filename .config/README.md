# Configuration Directory

This directory contains configuration files for development tools and testing.

## Files

- **pytest.ini** - Pytest configuration (test discovery, coverage, markers)
- **.pre-commit-config.yaml** - Pre-commit hooks for code quality
- **.yamllint.yml** - YAML linting rules
- **.dockerignore** - Docker build ignore patterns

## Note

These files are also copied to the project root for tool compatibility.
Some tools expect config files in the root directory.

## Build Artifacts

Build artifacts and test outputs are now organized in the `build/` directory:
- `build/htmlcov/` - HTML coverage reports
- `build/coverage.xml` - XML coverage report
- `build/test_output/` - Test execution outputs
