import subprocess
import html
import sys
import os
import json


def main():
    user_input = get_user_argument()
    html_content = run_python_scripts(user_input)
    write_output(html_content)


def get_user_argument():
    return input("Enter target domain to enumerate: ")


def run_python_scripts(user_input):
    current_dir = os.getcwd()
    scripts_dir = os.path.join(current_dir, "scripts")

    if not os.path.exists(scripts_dir):
        print(f"Scripts directory '{scripts_dir}' not found.")
        return

    scripts = []
    domain_list = []
    results = []
    
    for file in os.listdir(scripts_dir):
        if file.endswith(".py"):
            scripts.append(file)

    output, error = run_script("genDomain.py", user_input)
    d_results = f"<h2>Domains Generated</h2><pre>{output}</pre><pre style='color:red;'>{error}</pre>"
        
    lines = output.strip().split('\n')
    for line in lines:
        if line.startswith("Domain:"):
            domain_name = line.split(',')[0].split(':')[1].strip()
            domain_list.append(domain_name)
    
    for domain in domain_list:
        for script in scripts:
            script_path = os.path.join(scripts_dir, script)
            print(f"Running: {script} with domain - {domain}")
            output, error = run_script(script_path, domain)
            results.append(f"<div class='column'><h2>{script} - {domain}</h2><pre>{output}</pre><pre style='color:red;'>{error}</pre></div>")

    html_content = """
                    <html>
                        <head>
                            <title>MyLittlePuny</title>
                        
                            <style>
                                * {
                                    box-sizing: border-box;
                                    }

                                .column {
                                    float: left;
                                    width: 50%;
                                    padding: 10px;
                                    }

                                .row:after {
                                    content: "";
                                    display: table;
                                    clear: both;
                                    }
                            </style>
                        </head>
                    """
    
                    
    html_content +=  f"""
                        <body>
                            <h1>Python Script Execution Results</h1>
                            <div class='row'>
                                {d_results}
                            </row>
                            <div class='row'>
                                {''.join(results)}
                            </row>
                        </body>
                    </html>
                    """
    
    return html_content


def run_script(script_path, arg=None):
    output, error = "", ""

    try:
        args = [sys.executable, script_path]
        if arg:
            args.append(arg)
        
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=60,
            encoding='utf-8'  # Ensure UTF-8 encoding is used for both stdout and stderr
        )

        output = process.stdout
        error = process.stderr

    except subprocess.TimeoutExpired:
        error = f"Timeout: {script_path} took too long to execute."
    except Exception as e:
        error = str(e)

    if output is None:
        output = ""

    output = html.escape(output)

    return output, error


def write_output(html_content):
    output_file = "output.html"

    try:
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(html_content)

        print(f"Output saved to {output_file}")
    except Exception as e:
        print(f"Error saving output: {e}")


if __name__ == "__main__":
    main()
