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


def run_script(script_path, arg=None):
    """Runs a Python script with the given argument and captures output."""
    output, error = "", ""

    try:
        # Prepare the arguments for the subprocess
        args = [sys.executable, script_path]
        if arg:
            args.append(arg)  # Add argument if provided

        # Run the script with the appropriate arguments
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

    # Ensure output is not None
    if output is None:
        output = ""

    # Check if the output is valid JSON and handle accordingly
    if is_json_string(output):  # If output is in JSON format
        print("Output is a json shithead")
        json_output = json.loads(output)
        output = format_json_to_html_table(json_output)
    else:
        # If it's not JSON, escape it for HTML rendering
        print("Output is a string dumbfuck")
        output = html.escape(output)

    return output, error


def is_json_string(string):
    """Check if the provided string is a valid JSON format."""
    # Remove leading/trailing spaces
    string = string.strip()

    # Check if the string starts with '{' and ends with '}' (JSON Object)
    if string.startswith("{") and string.endswith("}"):
        try:
            # Attempt to load it as JSON
            json.loads(string)
            return True
        except ValueError:
            return False
    else:
        return False


def format_json_to_html_table(json_data):
    """Converts JSON data into an HTML table format."""
    print("Converting into tableformat\n\n\n")

    html_table = "<table border='1'><thead><tr>"

    # Create table headers and rows from the JSON structure
    try:
        results = json_data.get("data", {}).get(
            "attributes", {}).get("results", {})

        if results:  # Only create table if 'results' exists
            # Generate the table headers dynamically based on the keys in 'results'
            headers = list(results.keys())
            for header in headers:
                html_table += f"<th>{header}</th>"
            html_table += "</tr></thead><tbody>"

            # Generate rows based on values in 'results'
            for engine, details in results.items():
                html_table += "<tr>"
                for key, value in details.items():
                    html_table += f"<td>{value}</td>"
                html_table += "</tr>"

            html_table += "</tbody></table>"
        else:
            html_table = "No results available."

    except KeyError as e:
        # Handle missing expected keys in JSON structure
        html_table = f"Error: Missing expected key - {e}"

    return html_table


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
