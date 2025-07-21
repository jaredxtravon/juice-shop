import json
import os
import re
from openai import OpenAI
from pathlib import Path

def load_scan_results(sast_file="sonar-report.json", dast_file="zap-wrk/zap-report.json"):
    """Load SAST and DAST scan results from JSON files."""
    sast_results = {}
    dast_results = []
    if not os.path.exists(sast_file):
        print(f"SAST file {sast_file} not found")
    else:
        with open(sast_file, 'r') as f:
            sast_results = json.load(f)
    if not os.path.exists(dast_file):
        print(f"DAST file {dast_file} not found")
    else:
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

    # Process SonarCloud SAST results
    for issue in sast_results.get('issues', []):
        file_path = issue.get('component', '').replace('jaredxtravon_juice-shop:', '')
        rule_id = issue.get('rule', 'Unknown')
        message = issue.get('message', '')
        line_number = issue.get('line', 1)
        code_snippet, start_line, end_line = extract_vulnerable_code(file_path, line_number)
        
        prompt = f"""
You are a security expert analyzing vulnerabilities for OWASP Juice Shop, a JavaScript-based web application.
Below is a vulnerability from SonarCloud SAST:

- **File**: {file_path}
- **Rule**: {rule_id}
- **Message**: {message}
- **Line**: {line_number}
- **Code Snippet**:
```javascript
{code_snippet}
```

For this vulnerability:
1. Provide a specific fix (code or configuration).
2. Explain why it needs to be fixed, referencing OWASP Top 10 or Cheat Sheets.
3. Ensure the fix is compatible with OWASP Juice Shop.

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
        try:
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
        except Exception as e:
            analysis_output.append(f"Error analyzing issue in {file_path}: {str(e)}")

    # Process OWASP ZAP DAST results
    for alert in dast_results.get('alerts', []):
        alert_name = alert.get('alert', 'Unknown')
        description = alert.get('description', '')
        instances = alert.get('instances', [])
        for instance in instances:
            uri = instance.get('uri', '')
            prompt = f"""
You are a security expert analyzing vulnerabilities for OWASP Juice Shop, a JavaScript-based web application.
Below is a vulnerability from OWASP ZAP DAST:

- **Alert**: {alert_name}
- **Description**: {description}
- **URI**: {uri}
- **SAST Results (sample)**:
{json.dumps(sast_results.get('issues', [])[:5], indent=2)}

For this vulnerability:
1. Suggest a specific fix (code or configuration).
2. Explain why it needs to be fixed, referencing OWASP Top 10 or Cheat Sheets.
3. Ensure the fix is compatible with OWASP Juice Shop.

Format the response as:
### Vulnerability: [Alert Name]
**URI**: [URI]
**Description**: [Description]
**Fix**:
```javascript
[Fix or Configuration]
```
**Why Fix?**: [Explanation with OWASP reference]
"""
            try:
                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert specializing in secure web application practices."},
                        {"role": "user", "content": prompt}
                    ]
                )
                analysis = response.choices[0].message.content
                analysis_output.append(analysis)
            except Exception as e:
                analysis_output.append(f"Error analyzing DAST alert {alert_name}: {str(e)}")

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
