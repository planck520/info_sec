import json
import os
import requests
import hashlib
import sqlite3
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

class VulnerabilityAnalyzer:
    def __init__(self, base_url: str, api_key: str, output_dir: str = ".", model: str = "deepseek-chat"):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.rag_db = os.path.join(output_dir, "vulnerability_rag.db")
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
        
        # Removed confidence_score
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
    
    def build_chain_of_thought_prompt(self, vuln_info: Dict, code_content: str) -> str:
        """Build the chain-of-thought prompt (step 1), with strict format control."""

        # Build the path description
        path_description = ""
        if 'path' in vuln_info and vuln_info['path']:
            path_steps = []
            for i, node in enumerate(vuln_info['path']):
                step_desc = f"Step {i+1}: {node.get('func', 'unknown_function')}"
                if 'arg_index' in node:
                    step_desc += f"(arg {node['arg_index']})"
                path_steps.append(step_desc)
            path_description = " -> ".join(path_steps)
        else:
            path_description = f"{vuln_info['source_func']} -> {vuln_info['sink_func']}"

        prompt = f"""As a security expert, analyze whether the following C code contains a {vuln_info['vuln_type']} vulnerability. Reason step by step.

## Vulnerability Information
- **Vulnerability Type**: {vuln_info['vuln_type']}
- **Sink Function**: {vuln_info['sink_func']} (dangerous operation)
- **Source Function**: {vuln_info['source_func']} (input source)
- **Taint Propagation Path**: {path_description}

## Analysis Steps

### Step 1: Identify the Source Risk
- Determine whether `{vuln_info['source_func']}` receives externally controllable input
- Assess the trust level and risk of the input data
- **Key requirement**: distinguish external input from local configuration data. Use only explicit code evidence and do not guess
  - **Criteria for local configuration data**: classify the source as local configuration only if the code clearly shows one of the following patterns
    - **Pattern 1**: `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
      - Example: `JsonConf = getJsonConf(0); Var = websGetVar(JsonConf, "IpAddress", ...); cJSON_Delete(JsonConf);`
      - **Important**: although `websGetVar` appears here, it extracts a key from a JSON object, and the data source is the local configuration returned by `getJsonConf()`
      - `getJsonConf()` internally calls `cJSON_Parse()` to parse a local configuration file
    - **Pattern 2**: direct use of `cJSON_Parse()` to parse a local file
    - **Pattern 3**: clearly named local-file readers such as `readConfigFile()`
  - **Criteria for network-facing input**:
    - standalone use of `websGetVar(webs, key, ...)` to read parameters from an HTTP request, where the first argument is the webs request object rather than a JSON object
    - network input functions such as `recv()`, `read()`, and `recvfrom()`
  - **Key distinction**:
    - `websGetVar(JsonConf, ...)` where `JsonConf` comes from `getJsonConf()` -> local configuration, treated as safe input
    - `websGetVar(webs, ...)` where `webs` comes from an HTTP request -> network input, treated as unsafe input
  - **Do not infer local configuration from superficial call-pattern similarity**
    - Even if a function like `sub_XXXXX(a1, "key")` looks like key-value retrieval
    - If you cannot find explicit JSON-configuration handling in code, **do not** assume it is local configuration
  - **Conservative default**: if the data source cannot be determined, treat it as potentially externally controllable input

### Step 2: Trace the Taint Propagation Path
- Check whether the data is sanitized before it flows from the source to the sink
- Analyze whether each intermediate function validates, filters, or encodes the data
- Identify any possible breakpoints in taint propagation
- **Focus on the following protections**. Every judgment must rely on explicit code evidence rather than guesswork
  1. **Authentication check**: whether the code clearly performs login or authorization checks
     - For example: `if (g_Pass)`, `memcmp(path, "/login.html")`, or `check_login()`
     - You must point to concrete authentication logic in code rather than inferring it from a function name
  2. **Safe dynamic-allocation pattern** for CWE-119/120 buffer overflow:
     - **Key pattern**: `size = strlen(src); ptr = malloc(size + 1); if (ptr) strcpy(ptr, src);`
     - If the code first computes the source-string length with `strlen()`, then allocates `strlen(src) + 1`, and only then performs `strcpy` or `memcpy`
     - In this case, even dangerous functions such as `strcpy` do **not** imply a buffer overflow, and the path should be treated as **safe**
     - Example:
       ```c
       v2 = strlen(v1);
       v4 = malloc(v2 + 1);  // allocate enough space
       if (v4) strcpy(v4, v1);  // safe: destination size matches the source string
       ```
     - **Note**: this differs from a static buffer such as `char buf[256]`, which may still overflow
  3. **Service-enabled check**: whether the code verifies that the relevant service is enabled
     - For example: `if (!sslenable)` or `if (!ntp_enable)`
     - If the service is disabled, the path is unreachable
  4. **Input validation** for CWE-78 command injection: whether the code calls validation or filtering functions
     - For example: `Validity_check()`, `validate_input()`, or `filter_input()`
     - The validation call must be visible in code
  5. **Local-configuration source check** with strict criteria: whether the code clearly exhibits a local JSON-configuration pattern
     - **Pattern 1**: `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
       - In this case `websGetVar` extracts a value from a local JSON configuration object, not from a network request
       - The actual data source is a local configuration file loaded by `getJsonConf()`
     - **Pattern 2**: direct use of `cJSON_Parse()` to parse a file
     - **Do not** classify a source as local configuration based only on a call pattern such as `sub_XXX(a1, "key")`
     - **Key point**: distinguish `websGetVar(JsonConf, ...)` from `websGetVar(webs, ...)`

### Step 3: Analyze Sink Safety
- Check how `{vuln_info['sink_func']}` uses the incoming data
- Determine whether sufficient boundary checks, input validation, or other safeguards exist
- Evaluate whether the argument can be exploited by an attacker

### Step 4: Final Vulnerability Assessment
- Decide whether the code contains a real exploitable vulnerability based on the evidence above
- Assess the severity, exploit preconditions, and attack scenario
- **False-positive criteria**: classify the alert as a false positive or non-vulnerability if any of the following conditions is clearly supported by code evidence
  1. The code clearly contains an authentication check, such as `if (g_Pass)`, that blocks unauthorized access
  2. The code uses the **safe dynamic-allocation pattern** for CWE-119/120:
     - It computes the source length with `strlen(src)`
     - It allocates `strlen(src) + 1`
     - It then copies the data with `strcpy` or `memcpy`
     - Under this pattern, the destination buffer size matches the source data, so **there is no overflow risk**
  3. The code clearly checks whether the relevant service is enabled, such as `if (!sslenable)`, making the path unreachable when disabled
  4. The code clearly calls an input-validation function, such as `Validity_check(input)`, to filter invalid characters
  5. The code clearly shows a local JSON-configuration pattern, confirming that the data source is local configuration:
     - `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
     - Direct use of `cJSON_Parse()` to parse a local file
     - **Key point**: if `websGetVar(JsonConf, ...)` uses a `JsonConf` produced by `getJsonConf()`, it is local configuration rather than network input
- **Important principles**:
  - Every judgment must rely on explicit code evidence rather than similarity in function names or call patterns
  - For decompiled functions such as `sub_XXXXX`, do not assume they implement protections unless the decompiled body clearly shows them
  - If the evidence is uncertain, make a conservative judgment and treat the path as potentially risky rather than dismissing it as a false positive

## Code to Analyze
c
{code_content}
## Output Constraints (must be followed exactly)
Do not include any preamble such as "Okay", "As a security expert", or "Here is the analysis".

Do not include sections such as "Remediation Advice", "Security Recommendation", or "How to Fix".

You must follow the template below exactly. The output must be valid Markdown, and the heading names must not be changed.

## Output Template
### Step-by-Step Reasoning
#### Step 1: Identify the Source Risk
(Analyze in detail whether the source function receives externally controllable input, and discuss the trustworthiness of that input. Cite code lines or variable names.)
- **You must explicitly state** whether the data source is network input or local configuration
- **For local configuration**, use the following rules:
  - Pattern 1: the code contains `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
    - In this case, although `websGetVar` appears, the source is a local configuration file and should be classified as **local configuration**
  - Pattern 2: the code directly uses `cJSON_Parse()` to parse a file
- **For network input**, use the following rules:
  - `websGetVar(webs, key, ...)` where `webs` is an HTTP request object rather than a value returned by `getJsonConf()`
  - network input functions such as `recv()` and `read()`
- **Do not guess**: do not classify a source as local configuration based only on a call pattern such as `sub_XXX(a1, "key")`

#### Step 2: Trace the Taint Propagation Path
(Analyze in detail how data propagates from the source to the sink. Explain whether intermediate functions validate, filter, or truncate the data. If the path is broken, state that clearly.)
- **You must check** the following protections. If any of them clearly exists in code evidence, the alert can be judged as a false positive:
  1. A clearly visible authentication check, such as `if (g_Pass)` or `memcmp(path, "/login.html")`
  2. The **safe dynamic-allocation pattern** for buffer overflow:
     - Check whether the code contains `len = strlen(src); ptr = malloc(len + 1); if (ptr) strcpy(ptr, src);`
     - If the allocation size is computed from the source-string length (`strlen(src) + 1`), there is no overflow risk
     - **You must clearly see** all three steps: length computation, length-based allocation, and copy
  3. A clearly visible service-enabled check such as `if (!sslenable) return;`
  4. A clearly visible input-validation call such as `Validity_check(input)`
  5. A clearly visible local JSON-configuration pattern:
     - `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
     - direct use of `cJSON_Parse()` to parse a file
     - **Note**: distinguish `websGetVar(JsonConf, ...)` (local configuration) from `websGetVar(webs, ...)` (network input)
- **Important**: every conclusion must be backed by explicit code evidence, with concrete code lines when possible

#### Step 3: Analyze Sink Safety
(Analyze in detail how the sink function uses the incoming data. Check for boundary checks, length limits, or special-character escaping. Evaluate the sink in combination with the properties of the data from the source.)

#### Step 4: Final Vulnerability Assessment
(Based on the three steps above, conclude whether the code contains a real exploitable vulnerability. Discuss exploit preconditions and possible impact. Do not provide remediation advice.)
- If Step 2 finds any valid protection based on explicit code evidence, clearly state that the path is a **false positive**
- Only classify the alert as a real vulnerability if **all** of the following conditions hold:
  1. The data source is clearly externally controllable input, such as `websGetVar` or another network-facing interface
  2. No effective protection is present
  3. Every conclusion is based on explicit code evidence rather than guesswork
"""
        return prompt
    
    def call_deepseek_model(self, prompt: str, json_mode: bool = False) -> str:
        """Call the DeepSeek model."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 4096,
            "extra_body": {
                "chat_template_kwargs": {
                    "thinking": True
                }
            }
        }
        
        # Enable JSON mode when step 2 needs a structured verdict
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

    def get_verdict_from_llm(self, reasoning_chain: str) -> Dict:
        """Step 2: send the reasoning back to the LLM and obtain a clear JSON verdict."""

        verdict_prompt = f"""You are the final decision module of a security auditing system. Read the detailed vulnerability analysis below and produce the final verdict based on that analysis.

## Analysis
{reasoning_chain}

## Task
1. Read the analysis carefully.
2. Decide whether the code contains a **real exploitable** vulnerability.
3. **Classify as false (`is_vulnerable = false`)** only when the analysis provides explicit evidence for one of the following:
   - The analysis states that the path is broken, filtered, uncontrollable, non-vulnerable, or a false positive
   - The analysis clearly identifies any of these protections in code:
     - an authentication check, such as `if (g_Pass)` or `memcmp(path, "/login.html")`
     - the safe dynamic-allocation pattern, where the code computes `strlen(src)`, allocates `len + 1`, and then copies the data
       - the full pattern must be present, such as `v2 = strlen(v1); v4 = malloc(v2 + 1); if (v4) strcpy(v4, v1);`
       - under this pattern, the destination buffer matches the source length and there is no overflow risk
     - a service-enabled check, such as `if (!sslenable)`
     - an input-validation function, such as `Validity_check(input)`
     - a local JSON-configuration pattern:
       - `getJsonConf()` + `websGetVar(JsonConf, key, ...)` + `cJSON_Delete()`
       - direct use of `cJSON_Parse()` to parse a file
       - **Note**: if `websGetVar(JsonConf, ...)` uses a `JsonConf` returned by `getJsonConf()`, classify it as local configuration
   - **Important**: if the analysis relies only on guesses such as "the call pattern looks similar" or "it may be local configuration", do **not** classify it as a false positive
4. **Classify as true (`is_vulnerable = true`)** when:
   - the analysis explicitly concludes that a real exploitable vulnerability exists
   - the data comes from externally controllable input, such as:
     - `websGetVar(webs, key, ...)` reading from an HTTP request, where `webs` is not returned by `getJsonConf()`
     - network input functions such as `recv()` or `read()`
     - **Note**: `websGetVar(JsonConf, ...)` with `JsonConf` from `getJsonConf()` is local configuration, not external input
   - no effective protection is present, meaning the analysis did not find explicit code evidence of the protections listed above
5. **Conservative rule**:
   - If the analysis cannot determine the data source or protections, prefer `true` because the path remains risky
   - Do not classify the result as false based on speculation

## Output Format
Output only one valid JSON object. Do not include Markdown fences or any extra text:
{{
    "is_vulnerable": true or false
}}
"""
        try:
            logging.info("Requesting the final verdict from the model...")
            response_text = self.call_deepseek_model(verdict_prompt, json_mode=True)
            
            # Strip possible Markdown markers
            response_text = response_text.replace('```json', '').replace('```', '').strip()
            
            result_json = json.loads(response_text)
            
            # Ensure the required keys are present
            if 'is_vulnerable' not in result_json:
                # Fallback logic
                if 'true' in response_text.lower():
                    result_json['is_vulnerable'] = True
                else:
                    result_json['is_vulnerable'] = False
            
            return result_json
            
        except json.JSONDecodeError:
            logging.error("Error: unable to parse the verdict JSON returned by the model")
            return {'is_vulnerable': False} # Default to safe
        except Exception as e:
            logging.error(f"Error during verdict generation: {str(e)}")
            return {'is_vulnerable': False}

    def analyze_vulnerability_path(self, vuln_info: Dict, code_file_path: str) -> Dict:
        """Analyze a single vulnerability path."""
        
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
                'reasoning_chain': error_msg
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
                    'reasoning_chain': error_msg
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
        
        # 1. Generate the reasoning trace
        reasoning_prompt = self.build_chain_of_thought_prompt(vuln_info, code_content)
        reasoning_content = self.call_deepseek_model(reasoning_prompt)
        
        if not reasoning_content:
            return {'is_vulnerable': False, 'reasoning_chain': "Error: Model returned empty response", 'analysis_result': ""}

        # 2. Obtain the final verdict
        verdict_result = self.get_verdict_from_llm(reasoning_content)
        
        # Assemble the final result
        final_result = {
            'is_vulnerable': verdict_result['is_vulnerable'],
            'reasoning_chain': reasoning_content,
            'analysis_result': reasoning_content
        }
        
        # Save to the database
        self.save_analysis_result(code_hash, code_content, vuln_info, final_result)
        
        logging.info(f"Analysis complete: {'🔴 Vulnerable' if final_result['is_vulnerable'] else '🟢 Safe'}")
        
        return final_result
    
    def generate_report(self, analysis_results: List[Dict]) -> str:
        """Generate the analysis report."""
    
        report = f"# Vulnerability Analysis Report\n\n"
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
        
            if 'error' in result:
                report += f"**Error**: {result['error']}\n\n"
            else:
                report += f"**Detailed Analysis**:\n{result.get('analysis_result', 'N/A')}\n\n"
            
            # Add the reasoning chain
            if 'reasoning_chain' in result and len(result['reasoning_chain']) > 0:
                report += f"**Detailed Reasoning**:\n{result.get('reasoning_chain', 'N/A')}\n\n"
        
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

def process_directory(input_dir: str, base_input_dir: str, base_output_dir: str, analyzer: VulnerabilityAnalyzer):
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

            path_report = f"# Path {i} Analysis Report\n\n"
            path_report += f"**Vulnerability Type**: {result.get('vuln_type', 'N/A')}\n"
            path_report += f"**Sink Function**: {result.get('sink_func', 'N/A')}\n"
            path_report += f"**Source Function**: {result.get('source_func', 'N/A')}\n"
            path_report += f"**Vulnerability Present**: {'✅ Yes' if result.get('is_vulnerable') else '✅ No'}\n\n"

            if 'reasoning_chain' in result:
                path_report += f"**Detailed Analysis**:\n{result.get('reasoning_chain', 'N/A')}\n\n"

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
    log_file = os.path.join(log_dir, f"llm_analysis_{timestamp}.log")

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
    """Main entry point for batch-processing all firmware under the out directory."""
    # Switch to the root directory to support batch processing
    input_root = r""
    output_root = r""

    base_url = ""
    api_key = ""

    # Create the output directory
    os.makedirs(output_root, exist_ok=True)

    # Configure logging
    log_file = setup_logging(output_root)
    logging.info(f"Log file: {log_file}")

    if not os.path.exists(input_root):
        logging.error(f"Input root directory does not exist - {input_root}")
        return

    # Record the overall start time
    total_start_time = time.time()

    # Initialize the analyzer
    logging.info("Initializing the vulnerability analyzer...")
    analyzer = VulnerabilityAnalyzer(base_url, api_key, output_root)

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
    logging.info("Batch analysis completed!")
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
