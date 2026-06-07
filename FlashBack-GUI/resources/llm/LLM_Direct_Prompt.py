import json
import os
import requests
import hashlib
import sqlite3
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

class VulnerabilityAnalyzerWeakPrompt:
    """Vulnerability analyzer that uses the Weak-Prompt simplified prompt."""

    def __init__(self, base_url: str, api_key: str, output_dir: str = "."):
        self.base_url = base_url
        self.api_key = api_key
        self.rag_db = os.path.join(output_dir, "vulnerability_rag_weak.db")
        self.init_database()

    def init_database(self):
        """Initialize the RAG database."""
        conn = sqlite3.connect(self.rag_db)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vuln_type TEXT NOT NULL,
                sink_func TEXT NOT NULL,
                source_func TEXT NOT NULL,
                code_hash TEXT NOT NULL UNIQUE,
                analysis_result TEXT NOT NULL,
                is_vulnerable BOOLEAN NOT NULL,
                reasoning_chain TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS code_snippets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                code_content TEXT NOT NULL,
                path_info TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    def calculate_code_hash(self, code_content: str, path_info: Dict) -> str:
        """Compute the hash of a code snippet."""
        content = code_content + json.dumps(path_info, sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()

    def check_existing_analysis(self, code_hash: str) -> Optional[Dict]:
        """Check whether an analysis result already exists."""
        conn = sqlite3.connect(self.rag_db)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT analysis_result, is_vulnerable, reasoning_chain
            FROM analysis_results
            WHERE code_hash = ?
        ''', (code_hash,))

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                'analysis_result': result[0],
                'is_vulnerable': bool(result[1]),
                'reasoning_chain': result[2]
            }
        return None

    def save_analysis_result(self, code_hash: str, code_content: str,
                           path_info: Dict, analysis_result: Dict):
        """Save the analysis result to the database."""
        conn = sqlite3.connect(self.rag_db)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR IGNORE INTO code_snippets (code_hash, code_content, path_info)
            VALUES (?, ?, ?)
        ''', (code_hash, code_content, json.dumps(path_info)))

        cursor.execute('''
            INSERT INTO analysis_results
            (vuln_type, sink_func, source_func, code_hash, analysis_result,
             is_vulnerable, reasoning_chain)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            path_info['vuln_type'],
            path_info['sink_func'],
            path_info['source_func'],
            code_hash,
            analysis_result['analysis_result'],
            analysis_result['is_vulnerable'],
            analysis_result['reasoning_chain']
        ))

        conn.commit()
        conn.close()

    def build_simple_prompt(self, vuln_info: Dict, code_content: str) -> str:
        """Build the simplified Weak-Prompt prompt with structured guiding questions."""

        # Build the path description
        path_description = ""
        if 'path' in vuln_info and vuln_info['path']:
            path_steps = []
            for i, node in enumerate(vuln_info['path']):
                step_desc = f"{node.get('func', 'unknown_function')}"
                if 'arg_index' in node:
                    step_desc += f"(arg {node['arg_index']})"
                path_steps.append(step_desc)
            path_description = " -> ".join(path_steps)
        else:
            path_description = f"{vuln_info['source_func']} -> {vuln_info['sink_func']}"

        prompt = f"""You are a security researcher validating a potential {vuln_info['vuln_type']} vulnerability in firmware binary code.

Alert: Potential {vuln_info['vuln_type']} vulnerability
Sink Function: {vuln_info['sink_func']} (dangerous operation)
Source Function: {vuln_info['source_func']} (input source)
Data Flow Path: {path_description}

Code Context (decompiled):
```c
{code_content}
```

Guided Questions:
1) Where does the source data come from? Is it from user-controllable input (e.g., websGetVar, recv) or local configuration (e.g., getJsonConf, cJSON_Parse)?
2) Are there any security checks (authentication, input validation, boundary checks) between the source and sink?
3) For buffer operations: Are buffer sizes properly allocated? Is there length checking before copy/write operations?
4) For command injection: Are there input sanitizers or filters applied to the data?

Return a structured JSON answer:
{{
    "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE",
    "confidence": 0.0 to 1.0,
    "reasoning": ["bullet point 1", "bullet point 2", ...]
}}

Notes:
- TRUE_POSITIVE: Real exploitable vulnerability
- FALSE_POSITIVE: Safe or has sufficient mitigations
- Keep reasoning concise (2-4 bullet points)
"""
        return prompt

    def call_deepseek_model(self, prompt: str, json_mode: bool = False) -> str:
        """Call the DeepSeek model."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        payload = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 2048,  # Weak-Prompt uses a lower token limit
        }

        # Enable JSON mode when needed
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            logging.info("Calling the DeepSeek model for analysis...")
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=120
            )
            response.raise_for_status()

            result = response.json()
            logging.info("Model analysis completed!")
            return result['choices'][0]['message']['content']

        except requests.exceptions.Timeout:
            return "Error: model request timed out, please check the network connection or try again later"
        except requests.exceptions.ConnectionError:
            return "Error: unable to connect to the model server, please check the network connection"
        except requests.exceptions.HTTPError as e:
            return f"Error: HTTP request failed - {e.response.status_code} {e.response.reason}"
        except Exception as e:
            return f"Error: model invocation failed - {str(e)}"

    def analyze_vulnerability_path(self, vuln_info: Dict, code_file_path: str) -> Dict:
        """Analyze a single vulnerability path with the Weak-Prompt variant (direct verdict)."""

        # Read the code file
        try:
            with open(code_file_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
        except FileNotFoundError:
            error_msg = f"Error: code file does not exist - {code_file_path}"
            logging.error(error_msg)
            return {
                'error': error_msg,
                'is_vulnerable': False,
                'reasoning_chain': error_msg,
                'analysis_result': error_msg
            }
        except UnicodeDecodeError:
            # Try other encodings
            try:
                with open(code_file_path, 'r', encoding='latin-1') as f:
                    code_content = f.read()
            except Exception as e:
                error_msg = f"Error: unable to read the code file - {str(e)}"
                logging.error(error_msg)
                return {
                    'error': error_msg,
                    'is_vulnerable': False,
                    'reasoning_chain': error_msg,
                    'analysis_result': error_msg
                }

        # Compute the code hash
        code_hash = self.calculate_code_hash(code_content, vuln_info)

        # Check whether an analysis result already exists
        existing_analysis = self.check_existing_analysis(code_hash)
        if existing_analysis:
            logging.info(f"Using cached analysis result: {code_file_path}")
            return existing_analysis

        logging.info(f"Start analysis: {code_file_path}")
        logging.info(f"Vulnerability type: {vuln_info['vuln_type']}")
        logging.info(f"Source -> Sink: {vuln_info['source_func']} -> {vuln_info['sink_func']}")

        # Use the simplified prompt to obtain the verdict directly
        simple_prompt = self.build_simple_prompt(vuln_info, code_content)
        response_text = self.call_deepseek_model(simple_prompt, json_mode=True)

        if not response_text or "Error" in response_text:
            return {
                'is_vulnerable': False,
                'reasoning_chain': response_text or "Model returned empty response",
                'analysis_result': response_text or "Model returned empty response"
            }

            # Parse the JSON response
        try:
            # Strip possible Markdown markers
            response_text = response_text.replace('```json', '').replace('```', '').strip()
            result_json = json.loads(response_text)

            # Parse the new JSON format: {"verdict": "TRUE_POSITIVE/FALSE_POSITIVE", "confidence": 0-1, "reasoning": [...]}
            verdict = result_json.get('verdict', '').upper()
            confidence = result_json.get('confidence', 0.5)
            reasoning_list = result_json.get('reasoning', [])

            # Convert verdict into is_vulnerable
            if 'TRUE_POSITIVE' in verdict or 'TRUE' in verdict:
                is_vulnerable = True
            elif 'FALSE_POSITIVE' in verdict or 'FALSE' in verdict:
                is_vulnerable = False
            else:
                # Fallback logic
                if 'vuln' in response_text.lower() or 'positive' in response_text.lower():
                    is_vulnerable = True
                else:
                    is_vulnerable = False

            # Format the reasoning
            if isinstance(reasoning_list, list) and reasoning_list:
                reasoning_text = "Verdict: " + verdict + f" (Confidence: {confidence})\n\nReasoning:\n"
                for i, point in enumerate(reasoning_list, 1):
                    reasoning_text += f"{i}. {point}\n"
            else:
                reasoning_text = f"Verdict: {verdict} (Confidence: {confidence})"

            # Assemble the final result
            final_result = {
                'is_vulnerable': is_vulnerable,
                'reasoning_chain': reasoning_text,
                'analysis_result': reasoning_text,
                'confidence': confidence
            }

        except json.JSONDecodeError:
            logging.error("Error: unable to parse the JSON returned by the model")
            # Try to infer the result from plain text
            if 'true_positive' in response_text.lower() or 'vulnerable' in response_text.lower():
                is_vuln = True
            else:
                is_vuln = False

            final_result = {
                'is_vulnerable': is_vuln,
                'reasoning_chain': response_text,
                'analysis_result': response_text,
                'confidence': 0.5
            }

        # Save to the database
        self.save_analysis_result(code_hash, code_content, vuln_info, final_result)

        logging.info(f"Analysis complete: {'🔴 Vulnerable' if final_result['is_vulnerable'] else '🟢 Safe'}")

        return final_result

    def generate_report(self, analysis_results: List[Dict]) -> str:
        """Generate the analysis report."""

        report = f"# Vulnerability Analysis Report (Weak-Prompt)\n\n"
        report += f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        vulnerable_count = sum(1 for result in analysis_results if result.get('is_vulnerable', False))

        report += f"## Overview\n"
        report += f"- Total analyzed paths: {len(analysis_results)}\n"
        report += f"- Vulnerable paths: {vulnerable_count}\n"
        report += f"- Safe paths: {len(analysis_results) - vulnerable_count}\n\n"

        for i, result in enumerate(analysis_results, 1):
            report += f"## Path {i} Analysis Result\n"
            report += f"**Vulnerability Type**: {result.get('vuln_type', 'N/A')}\n"
            report += f"**Sink Function**: {result.get('sink_func', 'N/A')}\n"
            report += f"**Source Function**: {result.get('source_func', 'N/A')}\n"
            report += f"**Vulnerability Present**: {'✅ Yes' if result.get('is_vulnerable') else '✅ No'}\n"
            if 'confidence' in result:
                report += f"**Confidence**: {result.get('confidence', 'N/A')}\n"

            if 'error' in result:
                report += f"**Error**: {result['error']}\n\n"
            else:
                report += f"\n**Analysis Result**:\n{result.get('analysis_result', 'N/A')}\n\n"

            report += "---\n\n"

        # Add the summary section
        vulnerable_paths = [i for i, result in enumerate(analysis_results, 1)
                        if result.get('is_vulnerable', False)]

        if vulnerable_paths:
            report += f"## Security Recommendation\n"
            report += f"The following paths contain security risks and should be prioritized for fixing: {vulnerable_paths}\n"
        else:
            report += f"## Security Status\n"
            report += f"✅ No exploitable vulnerability was found in any analyzed path\n"

        return report

def find_json_directories(root_dir: str) -> List[str]:
    """Recursively find directories that contain JSON files."""
    json_dirs = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        json_files = [f for f in filenames if f.endswith('.json')]
        if json_files:
            json_dirs.append(dirpath)
    return json_dirs

def process_directory(input_dir: str, base_input_dir: str, base_output_dir: str, analyzer: VulnerabilityAnalyzerWeakPrompt):
    """Process all vulnerability paths in a single directory."""
    if not os.path.exists(input_dir):
        logging.error(f"Input directory does not exist - {input_dir}")
        return []

    json_files = [f for f in os.listdir(input_dir) if f.endswith('.json')]
    if not json_files:
        return []

    analysis_results = []

    # Compute the relative path to preserve the directory structure
    rel_path = os.path.relpath(input_dir, base_input_dir)
    output_subdir = os.path.join(base_output_dir, rel_path)
    os.makedirs(output_subdir, exist_ok=True)

    for json_file in json_files:
        json_path = os.path.join(input_dir, json_file)

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                vuln_paths = json.load(f)
            logging.info(f"Successfully loaded {len(vuln_paths)} vulnerability paths from {json_file}")
        except Exception as e:
            logging.error(f"Failed to read configuration file - {json_file}: {str(e)}")
            continue

        for i, vuln_info in enumerate(vuln_paths, 1):
            code_file = f"{i}.c"
            code_file_path = os.path.join(input_dir, code_file)

            logging.info(f"\n{'='*60}")
            logging.info(f"Analyzing path {i}/{len(vuln_paths)} - {rel_path}")

            result = analyzer.analyze_vulnerability_path(vuln_info, code_file_path)
            result.update(vuln_info)

            path_report = f"# Path {i} Analysis Report (Weak-Prompt)\n\n"
            path_report += f"**Vulnerability Type**: {result.get('vuln_type', 'N/A')}\n"
            path_report += f"**Sink Function**: {result.get('sink_func', 'N/A')}\n"
            path_report += f"**Source Function**: {result.get('source_func', 'N/A')}\n"
            path_report += f"**Vulnerability Present**: {'✅ Yes' if result.get('is_vulnerable') else '✅ No'}\n"
            if 'confidence' in result:
                path_report += f"**Confidence**: {result.get('confidence', 'N/A')}\n"
            path_report += "\n"

            if 'reasoning_chain' in result:
                path_report += f"**Analysis Result**:\n{result.get('reasoning_chain', 'N/A')}\n\n"

            report_file = os.path.join(output_subdir, f"{i}.md")
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(path_report)

            logging.info(f"Saved report for path {i} to: {report_file}")

            analysis_results.append(result)

    return analysis_results

def setup_logging(output_root: str):
    """Configure logging to write to both the console and a file."""
    log_dir = os.path.join(output_root, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Build the log file name with a timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"llm_analysis_weak_{timestamp}.log")

    # Configure the log format
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Create the logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    logger.handlers = []

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    # Add the handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return log_file

def main():
    """Main entry point for batch-processing all firmware under out (Weak-Prompt variant)."""
    # Change the output directory to llmtest_weak
    input_root = r""
    output_root = r""

    base_url = ""
    api_key = ""

    # Create the output directory
    os.makedirs(output_root, exist_ok=True)

    # Configure logging
    log_file = setup_logging(output_root)
    logging.info(f"Log file: {log_file}")
    logging.info("Using the Weak-Prompt variant for analysis")

    if not os.path.exists(input_root):
        logging.error(f"Input root directory does not exist - {input_root}")
        return

    # Record the overall start time
    total_start_time = time.time()

    # Initialize the analyzer
    logging.info("Initializing the vulnerability analyzer (Weak-Prompt)...")
    analyzer = VulnerabilityAnalyzerWeakPrompt(base_url, api_key, output_root)

    # Recursively find all directories that contain JSON files
    logging.info(f"\nScanning all directories under {input_root}...")
    json_dirs = find_json_directories(input_root)

    if not json_dirs:
        logging.info("No directories containing JSON files were found")
        return

    logging.info(f"Found {len(json_dirs)} directories containing JSON files")

    all_analysis_results = []
    dir_time_stats = []  # Processing time for each directory

    # Batch-process all directories
    for idx, json_dir in enumerate(json_dirs, 1):
        rel_path = os.path.relpath(json_dir, input_root)
        logging.info(f"\n>>>>> [{idx}/{len(json_dirs)}] Processing directory: {rel_path}")

        # Record the start time for this directory
        dir_start_time = time.time()

        results = process_directory(json_dir, input_root, output_root, analyzer)
        all_analysis_results.extend(results)

        # Compute the processing time for this directory
        dir_elapsed_time = time.time() - dir_start_time
        dir_time_stats.append({
            'path': rel_path,
            'time': dir_elapsed_time,
            'path_count': len(results)
        })

        # Report the processing time for this directory
        logging.info(f"[*] Completed directory {rel_path} in {dir_elapsed_time:.2f} seconds; analyzed {len(results)} paths")

    # Compute the total processing time
    total_elapsed_time = time.time() - total_start_time

    logging.info(f"\n{'='*60}")
    logging.info("Batch analysis completed! (Weak-Prompt)")
    logging.info(f"{'='*60}")

    if all_analysis_results:
        vulnerable_count = sum(1 for result in all_analysis_results if result.get('is_vulnerable', False))
        logging.info(f"Total analyzed paths: {len(all_analysis_results)}")
        logging.info(f"Vulnerable paths: {vulnerable_count}")
        logging.info(f"Safe paths: {len(all_analysis_results) - vulnerable_count}")
        logging.info(f"Database file: {analyzer.rag_db}")

        # Report time statistics
        logging.info(f"\n{'='*60}")
        logging.info("Time Statistics:")
        logging.info(f"{'='*60}")
        logging.info(f"Total processing time: {total_elapsed_time:.2f} seconds ({total_elapsed_time/60:.2f} minutes)")
        logging.info(f"Average per directory: {total_elapsed_time/len(dir_time_stats):.2f} seconds")
        logging.info(f"Average per path: {total_elapsed_time/len(all_analysis_results):.2f} seconds")

        # Report detailed per-directory timing
        logging.info(f"\nDetailed Time Statistics:")
        for stat in dir_time_stats:
            avg_per_path = stat['time'] / stat['path_count'] if stat['path_count'] > 0 else 0
            logging.info(f"  - {stat['path']}: {stat['time']:.2f} seconds ({stat['path_count']} paths, average {avg_per_path:.2f} seconds/path)")
    else:
        logging.info("No analyzable vulnerability paths were found")

if __name__ == "__main__":
    main()
