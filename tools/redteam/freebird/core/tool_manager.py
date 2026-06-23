import os
import subprocess
import argparse

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../tools/')  # Directory where all tools will be installed

def install_tool(tool_name, repo_url):
    tool_path = os.path.join(TOOLS_DIR, tool_name)

    if os.path.exists(tool_path):
        print(f"{tool_name} is already installed.")
        return

    # Clone the repository
    print(f"Cloning {repo_url}...")
    subprocess.run(['git', 'clone', repo_url, tool_path], check=True)

    # Set up a virtual environment if necessary
    venv_path = os.path.join(tool_path, 'venv')
    print(f"Setting up virtual environment for {tool_name}...")
    subprocess.run(['python3', '-m', 'venv', venv_path], check=True)

    # Activate virtual environment and install dependencies
    requirements_file = os.path.join(tool_path, 'requirements.txt')
    if os.path.exists(requirements_file):
        print(f"Installing dependencies for {tool_name}...")
        pip_bin = os.path.join(venv_path, 'bin', 'pip')
        subprocess.run([pip_bin, 'install', '-r', requirements_file], check=True)

    print(f"{tool_name} installed successfully.")

def install_tools_list(tools_list):
    for tool_name, repo_url in tools_list:
        install_tool(tool_name, repo_url)

def update_tool(tool_name):
    tool_path = os.path.join(TOOLS_DIR, tool_name)

    if not os.path.exists(tool_path):
        print(f"{tool_name} is not installed.")
        return

    # Pull the latest changes
    print(f"Updating {tool_name}...")
    subprocess.run(['git', '-C', tool_path, 'pull'], check=True)

    # Update dependencies if necessary
    venv_path = os.path.join(tool_path, 'venv')
    requirements_file = os.path.join(tool_path, 'requirements.txt')
    if os.path.exists(requirements_file):
        print(f"Updating dependencies for {tool_name}...")
        pip_bin = os.path.join(venv_path, 'bin', 'pip')
        subprocess.run([pip_bin, 'install', '-r', requirements_file], check=True)

    print(f"{tool_name} updated successfully.")

def remove_tool(tool_name):
    tool_path = os.path.join(TOOLS_DIR, tool_name)

    if not os.path.exists(tool_path):
        print(f"{tool_name} is not installed.")
        return

    # Remove the tool directory
    print(f"Removing {tool_name}...")
    subprocess.run(['rm', '-rf', tool_path], check=True)
    print(f"{tool_name} removed successfully.")

def show_status(tool_name):
    tool_path = os.path.join(TOOLS_DIR, tool_name)

    if os.path.exists(tool_path):
        print(f"{tool_name} is installed.")
    else:
        print(f"{tool_name} is not installed.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tool Manager for Freebird Framework')
    subparsers = parser.add_subparsers(dest='command', help='Subcommands')

    # Install command
    install_parser = subparsers.add_parser('install', help='Install a tool')
    install_parser.add_argument('tool_name', help='Name of the tool to install')
    install_parser.add_argument('repo_url', help='Git repository URL of the tool')

    # Install multiple tools
    install_list_parser = subparsers.add_parser('install-list', help='Install a list of tools')
    install_list_parser.add_argument('file', help='Path to a file containing the list of tools and their repositories')

    # Update command
    update_parser = subparsers.add_parser('update', help='Update a tool')
    update_parser.add_argument('tool_name', help='Name of the tool to update')

    # Remove command
    remove_parser = subparsers.add_parser('remove', help='Remove a tool')
    remove_parser.add_argument('tool_name', help='Name of the tool to remove')

    # Status command
    status_parser = subparsers.add_parser('status', help='Show the status of a tool')
    status_parser.add_argument('tool_name', help='Name of the tool')

    args = parser.parse_args()

    if args.command == 'install':
        install_tool(args.tool_name, args.repo_url)
    elif args.command == 'install-list':
        # Read the file to get a list of tools to install
        tools = []
        with open(args.file, 'r') as f:
            for line in f:
                name, url = line.strip().split(',')
                tools.append((name.strip(), url.strip()))
        install_tools_list(tools)
    elif args.command == 'update':
        update_tool(args.tool_name)
    elif args.command == 'remove':
        remove_tool(args.tool_name)
    elif args.command == 'status':
        show_status(args.tool_name)
    else:
        parser.print_help()
