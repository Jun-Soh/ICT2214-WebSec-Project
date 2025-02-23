import subprocess
import html
import sys
import os


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

    print(f"Searching for Python scripts in {scripts_dir}")

    scripts = []
    for file in os.listdir(scripts_dir):
        if file.endswith(".py"):
            scripts.append(file)

    results = []
    for script in scripts:
        script_path = os.path.join(scripts_dir, script)
        print(f"Running: {script}")
        output, error = run_script(script_path, user_input)
        results.append(
            f"<h2>{script}</h2><pre>{output}</pre><pre style='color:red;'>{error}</pre>")

    html_content = f"""
    <html>
    <head><title>Script Outputs</title></head>
    <body>
        <h1>Python Script Execution Results</h1>
        {''.join(results)}
    </body>
    </html>
    """

    return html_content


def run_script(script_path, arg):
    """Runs a Python script with the given argument and captures output."""
    output, error = "", ""

    try:
        process = subprocess.run(
            [sys.executable, script_path, arg],
            capture_output=True,
            text=True,
            timeout=60,
            encoding='utf-8'
        )
        output = process.stdout
        error = process.stderr

        # Escape HTML special characters in output and error
        output = html.escape(output)
        error = html.escape(error)

    except subprocess.TimeoutExpired:
        error = html.escape(
            f"Timeout: {script_path} took too long to execute.")
    except Exception as e:
        error = html.escape(str(e))

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
