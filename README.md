# AI-Powered Automated Code Reviewer

A Streamlit app that reviews source code for common bugs, security vulnerabilities, performance issues, coding-standard problems, and optimization opportunities.

The app works in two layers:

- Local static checks for multiple languages, with deeper Python AST checks.
- Optional OpenAI-enhanced review when `OPENAI_API_KEY` is configured.

## Features

- Paste code or upload a source file.
- Auto-detect language from file extension or choose a language manually.
- Generate clear review comments with severity, category, line number, plain-language explanations, and recommended fixes.
- Suggest improved snippets for common problems.
- Show code metrics and a best-practice checklist.
- Optionally call an OpenAI model for deeper contextual review.

## Run Locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

To enable AI-enhanced review:

```bash
set OPENAI_API_KEY=your_api_key_here
streamlit run app.py
```

On macOS/Linux, use:

```bash
export OPENAI_API_KEY=your_api_key_here
streamlit run app.py
```

## Notes

Static review tools are helpful, but they do not replace tests, linters, type checkers, security scanners, and human review for important code.
