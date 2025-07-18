import json
import os
import re
from openai import OpenAI
from pathlib import Path

def load_scan_results(sast_file="eslint-report.json", dast_file="zap-report.json"):
    """Load SAST and DAST scan results from JSON files."""
    sast_results = []
    dast_results = []
    if os.path.exists(sast_file):
        with open(sast_file, 'r') as f:
            sast_results = json.load(f)
    if os.path.exists(dast_file):
        with open(dast_file, 'r') as f:
            dast_results = json.load(f)
    return sast_results, dast_results

def extract_vulnerable_code(file_path, line_number, lines_before=2, lines_after=2):
    """Extract code snippet from file around the specified line number."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        start_line = max(1, line_number - lines_before)
        end_line = min(len(lines), line_number + lines_after)
        snippet = ''.join(lines[start_line-1:end_line])
        return snippet, start_line, end_line
    except Exception as e:
        return f"Error reading file {file_path}: {str(e)}", 0, 0

def analyze_with_openai(sast_results, dast_results):
    """Use OpenAI to analyze scan results, extract vulnerable code, and suggest fixes."""
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    analysis_output = []
    patched_files = {}

    for file_result in sast_results:
        file_path = file_result.get('filePath', '')
        for issue in file_result.get('messages', []):
            rule_id = issue.get('ruleId', 'Unknown')
            message = issue.get('message', '')
            line_number = issue.get('line', 1)
            code_snippet, start_line, end_line = extract_vulnerable_code(file_path, line_number)
            
            prompt = f"""
You are a security expert analyzing SAST scan results for a JavaScript web application (OWASP Juice Shop).
Below is a vulnerability found in the code:

- **File**: {file_path}
- **Rule**: {rule_id}
- **Message**: {message}
- **Line**: {line_number}
- **Code Snippet**:
```javascript
{code_snippet}
```

Additionally, DAST results from OWASP ZAP:
{json.dumps(dast_results, indent=2)[:1000]}

For this vulnerability:
1. Provide a specific code fix to replace the vulnerable code.
2. Explain why it needs to be fixed, referencing OWASP guidelines (e.g., OWASP Top 10, Cheat Sheets).
3. Ensure the fix is compatible with JavaScript and the OWASP Juice Shop application.

Format the response as:
### Vulnerability: [Rule ID]
**File**: [File Path]
**Line**: [Line Number]
**Description**: [Message]
**Vulnerable Code**:
```javascript
[Code Snippet]
```
**Fix**:
```javascript
[Fixed Code]
```
**Why Fix?**: [Explanation with OWASP reference]
"""
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in secure JavaScript coding practices."},
                    {"role": "user", "content": prompt}
                ]
            )
            analysis = response.choices[0].message.content
            analysis_output.append(analysis)

            fixed_code_match = re.search(r'```javascript\n(.*?)\n```', analysis, re.DOTALL)
            if fixed_code_match:
                fixed_code = fixed_code_match.group(1)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_lines = f.readlines()
                    fixed_lines = fixed_code.splitlines(keepends=True)
                    file_lines[start_line-1:end_line] = fixed_lines
                    patched_files[file_path] = ''.join(file_lines)
                except Exception as e:
                    analysis_output.append(f"Error patching {file_path}: {str(e)}")

    with open('ai-analysis-report.txt', 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(analysis_output))

    patched_dir = Path('patched_files')
    patched_dir.mkdir(exist_ok=True)
    for file_path, content in patched_files.items():
        relative_path = Path(file_path).relative_to(Path.cwd())
        patched_path = patched_dir / relative_path
        patched_path.parent.mkdir(parents=True, exist_ok=True)
        with open(patched_path, 'w', encoding='utf-8') as f:
            f.write(content)

    return '\n\n'.join(analysis_output)

def main():
    """Main function to load scan results and apply AI-driven fixes."""
    sast_results, dast_results = load_scan_results()
    analysis = analyze_with_openai(sast_results, dast_results)
    print(analysis)

if __name__ == "__main__":
    main()
