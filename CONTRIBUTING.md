# Contributing to Security Toolkit

Thank you for your interest in contributing! Please follow these guidelines:

## Code of Conduct

- Be respectful and professional
- No harassment or discrimination
- Report issues through GitHub issues

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/SecurityToolKit.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Install dependencies: `pip install -r requirements.txt`

## Making Changes

### Before You Start

- Check existing issues and pull requests
- Create an issue for major changes
- Keep changes focused and minimal

### Code Style

- Follow PEP 8 conventions
- Use meaningful variable and function names
- Add comments for complex logic
- No hardcoded API keys or sensitive data

### Testing

- Test locally before submitting PR
- Verify all features work as expected
- Test with Docker if applicable: `docker-compose run --rm toolkit`

### Adding New Tools

1. Create new script in `Tools/` folder
2. Add to `sec-tool.py` if integrating into main menu
3. Update `requirements.txt` if new dependencies needed
4. Update `README.md` with new feature documentation

## Submitting Changes

### Pull Requests

1. Update `README.md` with any new features
2. Write a clear PR description:
   - What problem does it solve?
   - How does it work?
   - Testing performed
3. Keep PR focused (one feature per PR)
4. Be prepared to make revisions based on feedback

### Commit Messages

- Use clear, descriptive messages
- Reference issues: `Fixes #123`
- Example: `Add URL filtering to log analyzer (closes #42)`

## Reporting Issues

### Before Reporting

- Check if issue already exists
- Test with latest code
- Gather system information (Python version, OS, etc.)

### Issue Template

```markdown
**Description**
Clear description of the problem

**Steps to Reproduce**

1. Step 1
2. Step 2

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**System Info**

- Python: 3.x
- OS: Linux/Mac/Windows
- Docker: Yes/No
```

## Security & Sensitive Data

- **Never commit API keys or credentials**
- Use `config.example.ini` for templates
- Check `.gitignore` is properly configured
- Report security issues privately (don't create public issues)

## Review Process

- Maintainer will review PR
- May request changes or improvements
- Once approved, your contribution will be merged
- You'll be credited in commit history

## Questions?

- Check `README.md` for usage
- Review `DOCKER_README.md` for Docker questions
- Open an issue with `[QUESTION]` tag

Thank you for contributing!
