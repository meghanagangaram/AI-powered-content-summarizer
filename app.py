import ast
import json
import os
import re
import textwrap
from dataclasses import dataclass
from typing import Iterable

import streamlit as st


LANGUAGES = {
    "Python": [".py"],
    "JavaScript / TypeScript": [".js", ".jsx", ".ts", ".tsx"],
    "Java": [".java"],
    "C / C++": [".c", ".cpp", ".cc", ".h", ".hpp"],
    "C#": [".cs"],
    "PHP": [".php"],
    "Ruby": [".rb"],
    "Go": [".go"],
    "SQL": [".sql"],
    "Other": [],
}


@dataclass
class Finding:
    category: str
    severity: str
    line: int | None
    title: str
    explanation: str
    recommendation: str
    snippet: str | None = None


def detect_language(filename: str, selected: str) -> str:
    if selected != "Auto detect":
        return selected

    suffix = os.path.splitext(filename.lower())[1]
    for language, extensions in LANGUAGES.items():
        if suffix in extensions:
            return language
    return "Other"


def line_for_offset(code: str, match: re.Match[str]) -> int:
    return code.count("\n", 0, match.start()) + 1


def add_regex_findings(
    findings: list[Finding],
    code: str,
    checks: Iterable[tuple[str, str, str, str, str, str, str | None]],
) -> None:
    for pattern, category, severity, title, explanation, recommendation, snippet in checks:
        for match in re.finditer(pattern, code, flags=re.IGNORECASE | re.MULTILINE):
            findings.append(
                Finding(
                    category=category,
                    severity=severity,
                    line=line_for_offset(code, match),
                    title=title,
                    explanation=explanation,
                    recommendation=recommendation,
                    snippet=snippet,
                )
            )


def analyze_python(code: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [
            Finding(
                "Bug",
                "High",
                exc.lineno,
                "Python syntax error",
                f"Python could not parse this file: {exc.msg}. The program may not run until this is fixed.",
                "Check the line shown, then run the file or tests again after fixing the syntax.",
            )
        ]

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            findings.append(
                Finding(
                    "Bug",
                    "Medium",
                    node.lineno,
                    "Bare except catches too much",
                    "A bare except also catches system-exiting exceptions and can hide real failures.",
                    "Catch the specific exception you expect and log enough context to debug it.",
                    "except ValueError as exc:\n    logger.warning('Invalid input: %s', exc)",
                )
            )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                findings.append(
                    Finding(
                        "Security",
                        "Critical",
                        node.lineno,
                        "Use of eval",
                        "eval runs text as code. If user-controlled input reaches it, attackers can execute commands.",
                        "Use a parser, lookup table, or ast.literal_eval for simple Python literals.",
                        "from ast import literal_eval\nvalue = literal_eval(user_input)",
                    )
                )
            if node.func.id == "exec":
                findings.append(
                    Finding(
                        "Security",
                        "Critical",
                        node.lineno,
                        "Use of exec",
                        "exec executes arbitrary Python statements, which is dangerous with dynamic input.",
                        "Replace dynamic execution with explicit functions or a restricted command map.",
                    )
                )

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "execute" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.JoinedStr) or (
                    isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod))
                ):
                    findings.append(
                        Finding(
                            "Security",
                            "High",
                            node.lineno,
                            "Possible SQL injection",
                            "Building SQL by combining strings can let untrusted input change the query.",
                            "Use parameterized queries from your database driver.",
                            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                        )
                    )

    long_lines = [idx for idx, line in enumerate(code.splitlines(), start=1) if len(line) > 100]
    if long_lines:
        findings.append(
            Finding(
                "Coding standard",
                "Low",
                long_lines[0],
                "Long lines reduce readability",
                f"{len(long_lines)} line(s) are longer than 100 characters.",
                "Wrap complex expressions and use named variables for intermediate values.",
            )
        )

    add_regex_findings(
        findings,
        code,
        [
            (
                r"^\s*print\s*\(",
                "Coding standard",
                "Low",
                "Debug print left in code",
                "print calls are easy to miss and can leak noisy output in production.",
                "Use structured logging with levels instead of print statements.",
                "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('message')",
            ),
            (
                r"password\s*=\s*['\"][^'\"]+['\"]",
                "Security",
                "High",
                "Hard-coded password",
                "Secrets in source code can be copied, logged, or committed accidentally.",
                "Load secrets from environment variables or a secret manager.",
                "password = os.environ['APP_PASSWORD']",
            ),
        ],
    )

    return findings


def analyze_generic(code: str, language: str) -> list[Finding]:
    findings: list[Finding] = []

    common_checks = [
        (
            r"(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "Security",
            "High",
            "Possible hard-coded secret",
            "Secrets stored in code can leak through commits, logs, screenshots, and deployments.",
            "Move secrets into environment variables or a managed vault, then rotate the exposed value.",
            "const apiKey = process.env.API_KEY;",
        ),
        (
            r"SELECT\s+.+\s+\+\s*",
            "Security",
            "High",
            "Possible SQL query concatenation",
            "Concatenating SQL strings can allow attackers to change the query.",
            "Use prepared statements or parameterized queries.",
            None,
        ),
        (
            r"\bTODO\b|\bFIXME\b",
            "Best practice",
            "Low",
            "Unresolved TODO/FIXME",
            "TODO markers are useful while building, but they often become forgotten production debt.",
            "Convert this into a tracked issue or finish it before release.",
            None,
        ),
        (
            r"console\.log\s*\(",
            "Coding standard",
            "Low",
            "Console logging in application code",
            "Debug logs can clutter browser output and may expose internal values.",
            "Use the project logger or remove debug output before shipping.",
            None,
        ),
    ]
    add_regex_findings(findings, code, common_checks)

    lines = code.splitlines()
    if len(lines) > 500:
        findings.append(
            Finding(
                "Maintainability",
                "Medium",
                1,
                "Large file",
                "Large files are harder to review, test, and reuse.",
                "Split unrelated responsibilities into smaller modules or components.",
            )
        )

    duplicate_blocks = find_duplicate_blocks(lines)
    if duplicate_blocks:
        first_line, repeated_line = duplicate_blocks
        findings.append(
            Finding(
                "Optimization",
                "Medium",
                repeated_line,
                "Repeated code block",
                "The same block appears more than once, which makes future fixes easier to miss.",
                f"Extract the repeated logic near lines {first_line} and {repeated_line} into a function.",
            )
        )

    if language in {"JavaScript / TypeScript", "Java", "C / C++", "C#", "PHP"}:
        add_regex_findings(
            findings,
            code,
            [
                (
                    r"\bfor\s*\([^)]*\)\s*\{[\s\S]{0,300}\bfor\s*\(",
                    "Performance",
                    "Medium",
                    "Nested loop",
                    "Nested loops can become slow when both collections grow.",
                    "Check the expected input size. A map, set, index, or precomputed lookup may reduce the work.",
                    None,
                ),
                (
                    r"catch\s*\([^)]*\)\s*\{\s*\}",
                    "Bug",
                    "Medium",
                    "Empty catch block",
                    "Ignoring exceptions hides failures and makes production bugs hard to diagnose.",
                    "Handle the error, add context-rich logging, or let it propagate.",
                    None,
                ),
            ],
        )

    return findings


def find_duplicate_blocks(lines: list[str]) -> tuple[int, int] | None:
    seen: dict[tuple[str, ...], int] = {}
    normalized = [line.strip() for line in lines]

    for idx in range(0, max(0, len(normalized) - 5)):
        block = tuple(line for line in normalized[idx : idx + 5] if line and not line.startswith(("//", "#")))
        if len(block) < 4:
            continue
        if block in seen:
            return seen[block] + 1, idx + 1
        seen[block] = idx
    return None


def summarize_metrics(code: str) -> dict[str, int]:
    lines = code.splitlines()
    return {
        "Lines": len(lines),
        "Non-empty": sum(1 for line in lines if line.strip()),
        "Comments": sum(1 for line in lines if line.strip().startswith(("#", "//", "/*", "*"))),
        "Characters": len(code),
    }


def severity_rank(finding: Finding) -> int:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return order.get(finding.severity, 4)


def local_review(code: str, language: str) -> list[Finding]:
    findings = analyze_python(code) if language == "Python" else []
    findings.extend(analyze_generic(code, language))

    if not findings:
        findings.append(
            Finding(
                "Best practice",
                "Info",
                None,
                "No obvious issues found by local checks",
                "The local reviewer did not find common bug, security, style, or performance patterns.",
                "Still run tests, linters, type checks, and a human review for important changes.",
            )
        )

    return sorted(findings, key=severity_rank)


def build_ai_prompt(code: str, language: str, local_findings: list[Finding]) -> str:
    compact_findings = [
        {
            "category": item.category,
            "severity": item.severity,
            "line": item.line,
            "title": item.title,
            "explanation": item.explanation,
            "recommendation": item.recommendation,
        }
        for item in local_findings[:12]
    ]

    return f"""
You are a senior code reviewer. Review the following {language} source code for bugs, security vulnerabilities,
performance issues, coding standard violations, and optimization opportunities.

Return concise Markdown with these sections:
1. Overall assessment
2. Review comments with line numbers when possible
3. Improved code snippets
4. Simple-language explanations
5. Best-practice recommendations

Local static-analysis findings:
{json.dumps(compact_findings, indent=2)}

Source code:
```{language.lower()}
{code[:14000]}
```
"""


def run_ai_review(code: str, language: str, findings: list[Finding], model: str) -> str:
    try:
        from openai import OpenAI

        client = OpenAI()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You produce practical, accurate, kind code reviews for working engineers.",
                },
                {"role": "user", "content": build_ai_prompt(code, language, findings)},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content or ""
    except Exception as exc:
        return f"AI review could not run: {exc}"


def render_finding(finding: Finding) -> None:
    line_text = f"Line {finding.line}" if finding.line else "General"
    st.markdown(f"**{finding.severity} - {finding.category}: {finding.title}**  \n{line_text}")
    st.write(finding.explanation)
    st.info(finding.recommendation)
    if finding.snippet:
        st.code(finding.snippet)


def main() -> None:
    st.set_page_config(page_title="AI Code Reviewer", page_icon="CR", layout="wide")

    st.title("AI-Powered Automated Code Reviewer")
    st.caption("Review source code for bugs, security risks, performance issues, standards, and practical improvements.")

    with st.sidebar:
        st.header("Review settings")
        language_choice = st.selectbox("Language", ["Auto detect", *LANGUAGES.keys()])
        use_ai = st.toggle("Enhance with OpenAI", value=bool(os.getenv("OPENAI_API_KEY")))
        model = st.text_input("OpenAI model", value=os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
        st.divider()
        st.write("Optional AI review uses `OPENAI_API_KEY` from your environment.")

    uploaded = st.file_uploader("Upload a source file", type=None)
    filename = uploaded.name if uploaded else "pasted-code.py"

    default_code = textwrap.dedent(
        """
        import os

        password = "super-secret-password"

        def get_user(cursor, user_id):
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            print("Fetched user")
            return cursor.fetchone()
        """
    ).strip()

    if uploaded:
        code = uploaded.read().decode("utf-8", errors="replace")
    else:
        code = st.text_area("Paste source code", value=default_code, height=360)

    detected_language = detect_language(filename, language_choice)

    col_a, col_b, col_c, col_d = st.columns(4)
    metrics = summarize_metrics(code)
    col_a.metric("Language", detected_language)
    col_b.metric("Lines", metrics["Lines"])
    col_c.metric("Non-empty", metrics["Non-empty"])
    col_d.metric("Comments", metrics["Comments"])

    if st.button("Run review", type="primary", use_container_width=True):
        if not code.strip():
            st.warning("Paste or upload code before running a review.")
            return

        findings = local_review(code, detected_language)
        st.subheader("Review comments")

        for finding in findings:
            with st.container(border=True):
                render_finding(finding)

        st.subheader("Best-practice checklist")
        st.markdown(
            """
- Add tests around changed behavior and edge cases.
- Run the language's formatter, linter, and type checker before merging.
- Keep secrets out of source code and rotate any value that was committed.
- Prefer simple, named functions over deeply nested control flow.
- Measure performance before and after optimization work.
"""
        )

        if use_ai:
            if not os.getenv("OPENAI_API_KEY"):
                st.warning("Set `OPENAI_API_KEY` to enable the AI-enhanced review.")
            else:
                with st.spinner("Asking the AI reviewer for deeper feedback..."):
                    ai_review = run_ai_review(code, detected_language, findings, model)
                st.subheader("AI-enhanced review")
                st.markdown(ai_review)


if __name__ == "__main__":
    main()
