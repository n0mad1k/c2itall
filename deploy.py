#!/usr/bin/env python3
"""
C2ingRed - Main deployment menu and orchestrator
Modular red team infrastructure deployment tool
"""

import os
import sys
import subprocess
import importlib.util
import argparse
from datetime import datetime

# Add utils to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))

from utils.common import COLORS, clear_screen, print_banner, wait_for_input, confirm_action, archive_old_logs

def import_module_from_path(module_name, file_path):
    """Dynamically import a module from a file path"""
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        print(f"{COLORS['RED']}Error importing {module_name}: {e}{COLORS['RESET']}")
        return None

def main_menu():
    """Display the main menu and handle user selection"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}MAIN MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}=========={COLORS['RESET']}")
        print(f"1) Deploy Attack Box")
        print(f"2) Deploy C2 Infrastructure") 
        print(f"3) Deploy Redirector")
        print(f"4) Deploy Phishing Infrastructure")
        print(f"5) Deploy Payload Server")
        print(f"6) Deploy Email Tracker")
        print(f"7) Deploy Logging Server {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"8) Deploy Share-Drive {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"9) Deploy Hashtopolis {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"10) Deploy Chat Server {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"11) Tools & Utilities")
        print(f"12) Cleanup & Teardown")
        print(f"\n99) Exit")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            deploy_attack_box()
        elif choice == "2":
            deploy_c2_infrastructure()
        elif choice == "3":
            deploy_redirector()
        elif choice == "4":
            deploy_phishing_infrastructure()
        elif choice == "5":
            deploy_payload_server()
        elif choice == "6":
            deploy_tracker()
        elif choice in ["7", "8", "9", "10"]:
            print(f"\n{COLORS['YELLOW']}This feature is currently under construction.{COLORS['RESET']}")
            wait_for_input()
        elif choice == "11":
            tools_menu()
        elif choice == "12":
            cleanup_menu()
        elif choice == "99":
            print(f"\n{COLORS['GREEN']}Exiting C2ingRed. Goodbye!{COLORS['RESET']}")
            sys.exit(0)
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def deploy_c2_infrastructure():
    """Launch the C2 infrastructure deployment module"""
    archive_logs_before_deployment()
    
    c2_module_path = os.path.join(os.path.dirname(__file__), 'modules', 'c2', 'deploy_c2.py')
    
    if not os.path.exists(c2_module_path):
        print(f"\n{COLORS['RED']}C2 deployment module not found at: {c2_module_path}{COLORS['RESET']}")
        wait_for_input()
        return
    
    c2_module = import_module_from_path('deploy_c2', c2_module_path)
    if c2_module:
        c2_module.c2_menu()

def deploy_redirector():
    """Launch the redirector deployment module"""
    archive_logs_before_deployment()
    
    redirector_module_path = os.path.join(os.path.dirname(__file__), 'modules', 'redirectors', 'deploy_redirector.py')
    
    if not os.path.exists(redirector_module_path):
        print(f"\n{COLORS['RED']}Redirector deployment module not found at: {redirector_module_path}{COLORS['RESET']}")
        wait_for_input()
        return
    
    redirector_module = import_module_from_path('deploy_redirector', redirector_module_path)
    if redirector_module:
        redirector_module.redirector_menu()

def deploy_phishing_infrastructure():
    """Launch the phishing infrastructure deployment module"""
    archive_logs_before_deployment()
    
    phishing_module_path = os.path.join(os.path.dirname(__file__), 'modules', 'phishing', 'deploy_phishing.py')
    
    if not os.path.exists(phishing_module_path):
        print(f"\n{COLORS['RED']}Phishing deployment module not found at: {phishing_module_path}{COLORS['RESET']}")
        wait_for_input()
        return
    
    phishing_module = import_module_from_path('deploy_phishing', phishing_module_path)
    if phishing_module:
        phishing_module.phishing_menu()

def deploy_payload_server():
    """Launch the payload server deployment module"""
    archive_logs_before_deployment()
    
    payload_module_path = os.path.join(os.path.dirname(__file__), 'modules', 'payload-server', 'deploy_payload.py')
    
    if not os.path.exists(payload_module_path):
        print(f"\n{COLORS['RED']}Payload server deployment module not found at: {payload_module_path}{COLORS['RESET']}")
        wait_for_input()
        return
    
    payload_module = import_module_from_path('deploy_payload', payload_module_path)
    if payload_module:
        payload_module.payload_menu()

def deploy_tracker():
    """Deploy email tracking server"""
    print(f"\n{COLORS['BLUE']}Email Tracker Deployment{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}This would deploy a standalone email tracking server{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Feature coming soon...{COLORS['RESET']}")
    wait_for_input()

def deploy_attack_box():
    """Launch the attack box deployment module"""
    archive_logs_before_deployment()
    
    attack_box_module_path = os.path.join(os.path.dirname(__file__), 'modules', 'attack-box', 'deploy_attack_box.py')
    
    if not os.path.exists(attack_box_module_path):
        print(f"\n{COLORS['RED']}Attack box deployment module not found at: {attack_box_module_path}{COLORS['RESET']}")
        wait_for_input()
        return
    
    attack_box_module = import_module_from_path('deploy_attack_box', attack_box_module_path)
    if attack_box_module:
        attack_box_module.attack_box_menu()

def tools_menu():
    """Display the tools submenu"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}TOOLS & UTILITIES MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}======================{COLORS['RESET']}")
        print(f"1) Generate SSH Keys")
        print(f"2) Test Provider Connectivity")
        print(f"3) Validate Configuration Files")
        print(f"4) Network Reconnaissance Tools {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"5) Payload Generation Tools {COLORS['GRAY']}*UNDER-CONSTRUCTION*{COLORS['RESET']}")
        print(f"6) Infrastructure Health Check")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            generate_ssh_keys()
        elif choice == "2":
            test_provider_connectivity()
        elif choice == "3":
            validate_configurations()
        elif choice in ["4", "5"]:
            print(f"\n{COLORS['YELLOW']}This feature is currently under construction.{COLORS['RESET']}")
            wait_for_input()
        elif choice == "6":
            infrastructure_health_check()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def cleanup_menu():
    """Display the cleanup submenu"""
    while True:
        clear_screen()
        print_banner()
        print(f"{COLORS['WHITE']}CLEANUP & TEARDOWN MENU{COLORS['RESET']}")
        print(f"{COLORS['WHITE']}======================={COLORS['RESET']}")
        print(f"1) Interactive Teardown (Select from List)")
        print(f"2) Teardown by Deployment ID")
        print(f"3) Teardown All Infrastructure")
        print(f"4) Clean Local SSH Keys")
        print(f"5) Manage Log Files & Archive")
        print(f"6) List Active Deployments")
        print(f"99) Return to Main Menu")
        
        choice = input(f"\nSelect an option: ")
        
        if choice == "1":
            interactive_teardown()
        elif choice == "2":
            teardown_by_id()
        elif choice == "3":
            teardown_all()
        elif choice == "4":
            clean_ssh_keys()
        elif choice == "5":
            clean_logs()
        elif choice == "6":
            list_deployments()
        elif choice == "99":
            return
        else:
            print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
            wait_for_input()

def generate_ssh_keys():
    """Generate SSH keys utility"""
    from utils.ssh_utils import generate_ssh_key
    from utils.common import generate_deployment_id
    
    print(f"\n{COLORS['BLUE']}SSH Key Generation{COLORS['RESET']}")
    
    key_name = input("Enter key name (or leave blank for auto-generated): ")
    if not key_name:
        key_name = generate_deployment_id()
    
    ssh_key_path = generate_ssh_key(key_name)
    if ssh_key_path:
        print(f"{COLORS['GREEN']}SSH key generated successfully!{COLORS['RESET']}")
        print(f"Private key: {ssh_key_path}")
        print(f"Public key: {ssh_key_path}.pub")
    else:
        print(f"{COLORS['RED']}Failed to generate SSH key{COLORS['RESET']}")
    
    wait_for_input()

def test_provider_connectivity():
    """Test connectivity to cloud providers"""
    print(f"\n{COLORS['BLUE']}Provider Connectivity Test{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}This would test connectivity to AWS, Linode, and FlokiNET{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Feature coming soon...{COLORS['RESET']}")
    wait_for_input()

def validate_configurations():
    """Validate configuration files"""
    print(f"\n{COLORS['BLUE']}Configuration Validation{COLORS['RESET']}")
    
    config_dirs = ['providers/AWS', 'providers/Linode', 'providers/FlokiNET']
    
    for config_dir in config_dirs:
        vars_file = os.path.join(config_dir, 'vars.yaml')
        if os.path.exists(vars_file):
            print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found: {vars_file}")
        else:
            print(f"{COLORS['RED']}✗{COLORS['RESET']} Missing: {vars_file}")
    
    wait_for_input()

def infrastructure_health_check():
    """Check health of deployed infrastructure"""
    print(f"\n{COLORS['BLUE']}Infrastructure Health Check{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}This would check the status of deployed infrastructure{COLORS['RESET']}")
    print(f"{COLORS['YELLOW']}Feature coming soon...{COLORS['RESET']}")
    wait_for_input()

def interactive_teardown():
    """Interactive teardown - directly select deployment to teardown"""
    try:
        # Clear screen and run teardown script with --select option
        clear_screen()
        print(f"{COLORS['CYAN']}Select Deployment to Teardown...{COLORS['RESET']}\n")
        
        # Run the teardown script directly with --select to bypass the menu
        os.system(f"{sys.executable} teardown.py --select")
        
        # Return to cleanup menu after teardown completes
        print(f"\n{COLORS['CYAN']}Teardown process completed.{COLORS['RESET']}")
        wait_for_input()
    except Exception as e:
        print(f"{COLORS['RED']}Error: {str(e)}{COLORS['RESET']}")
        wait_for_input()

def teardown_by_id():
    """Teardown deployment by ID using standalone teardown script"""
    print(f"\n{COLORS['BLUE']}Teardown by Deployment ID{COLORS['RESET']}")
    
    deployment_id = input("Enter deployment ID: ").strip()
    if not deployment_id:
        print(f"{COLORS['YELLOW']}No deployment ID provided{COLORS['RESET']}")
        wait_for_input()
        return
    
    try:
        result = subprocess.run([sys.executable, "teardown.py", "--deployment-id", deployment_id], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{COLORS['RED']}Error running teardown: {result.stderr}{COLORS['RESET']}")
        else:
            print(result.stdout)
    except Exception as e:
        print(f"{COLORS['RED']}Error: {str(e)}{COLORS['RESET']}")
    wait_for_input()

def teardown_all():
    """Teardown all infrastructure"""
    print(f"\n{COLORS['RED']}⚠️  WARNING: This will teardown ALL infrastructure!{COLORS['RESET']}")
    
    confirm = input(f"{COLORS['YELLOW']}Are you sure? Type 'DESTROY' to confirm: {COLORS['RESET']}")
    if confirm != "DESTROY":
        print(f"{COLORS['GREEN']}Operation cancelled{COLORS['RESET']}")
        wait_for_input()
        return
    
    # Use the standalone teardown script
    teardown_script = os.path.join(os.path.dirname(__file__), 'teardown.py')
    try:
        result = subprocess.run([
            sys.executable, teardown_script, 
            '--all', 
            '--force'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"\n{COLORS['GREEN']}All infrastructure has been torn down{COLORS['RESET']}")
        else:
            print(f"\n{COLORS['RED']}Some teardown operations failed{COLORS['RESET']}")
            if result.stderr:
                print(f"Error: {result.stderr}")
    except Exception as e:
        print(f"\n{COLORS['RED']}Error running teardown: {e}{COLORS['RESET']}")
    
    wait_for_input()

def clean_ssh_keys():
    """Clean local SSH keys"""
    print(f"\n{COLORS['BLUE']}Clean Local SSH Keys{COLORS['RESET']}")
    
    ssh_dir = os.path.expanduser("~/.ssh")
    c2deploy_keys = []
    
    if os.path.exists(ssh_dir):
        for file in os.listdir(ssh_dir):
            if file.startswith("c2deploy_"):
                c2deploy_keys.append(os.path.join(ssh_dir, file))
    
    if not c2deploy_keys:
        print(f"{COLORS['GREEN']}No C2ingRed SSH keys found{COLORS['RESET']}")
    else:
        print(f"Found {len(c2deploy_keys)} C2ingRed SSH keys:")
        for key in c2deploy_keys:
            print(f"  {key}")
        
        if input(f"\n{COLORS['YELLOW']}Delete these keys? (y/n): {COLORS['RESET']}").lower() == 'y':
            for key in c2deploy_keys:
                try:
                    os.remove(key)
                    print(f"{COLORS['GREEN']}Removed: {key}{COLORS['RESET']}")
                except Exception as e:
                    print(f"{COLORS['RED']}Failed to remove {key}: {e}{COLORS['RESET']}")
    
    wait_for_input()

def clean_logs():
    """Clean log files and manage archive"""
    print(f"\n{COLORS['BLUE']}Log File Management{COLORS['RESET']}")
    
    logs_dir = "logs"
    archive_dir = os.path.join(logs_dir, "archive")
    
    if not os.path.exists(logs_dir):
        print(f"{COLORS['GREEN']}No logs directory found{COLORS['RESET']}")
        wait_for_input()
        return
    
    # Count current log files
    log_files = [f for f in os.listdir(logs_dir) if f.endswith('.log') and os.path.isfile(os.path.join(logs_dir, f))]
    info_files = [f for f in os.listdir(logs_dir) if f.startswith('deployment_info_') and f.endswith('.txt')]
    
    # Count archived files
    archived_files = []
    if os.path.exists(archive_dir):
        archived_files = [f for f in os.listdir(archive_dir) if f.endswith('.log') or f.endswith('.txt')]
    
    print(f"Current logs: {len(log_files)} log files, {len(info_files)} info files")
    print(f"Archived files: {len(archived_files)} files")
    
    print(f"\nOptions:")
    print(f"1) Archive old logs (keep 10 most recent)")
    print(f"2) Delete current log files")
    print(f"3) Clean archive directory")
    print(f"4) View log files")
    print(f"5) Return to menu")
    
    choice = input(f"\nSelect an option: ")
    
    if choice == "1":
        from utils.common import archive_old_logs
        print(f"\n{COLORS['BLUE']}Archiving old logs...{COLORS['RESET']}")
        archive_old_logs(max_logs_to_keep=10)
        print(f"{COLORS['GREEN']}Archive operation completed{COLORS['RESET']}")
        
    elif choice == "2":
        if not log_files and not info_files:
            print(f"{COLORS['GREEN']}No current log files found{COLORS['RESET']}")
        else:
            print(f"Current log files:")
            for log_file in log_files + info_files:
                print(f"  {log_file}")
            
            if input(f"\n{COLORS['YELLOW']}Delete these current log files? (y/n): {COLORS['RESET']}").lower() == 'y':
                for log_file in log_files + info_files:
                    try:
                        os.remove(os.path.join(logs_dir, log_file))
                        print(f"{COLORS['GREEN']}Removed: {log_file}{COLORS['RESET']}")
                    except Exception as e:
                        print(f"{COLORS['RED']}Failed to remove {log_file}: {e}{COLORS['RESET']}")
    
    elif choice == "3":
        if not os.path.exists(archive_dir) or not archived_files:
            print(f"{COLORS['GREEN']}No archived files found{COLORS['RESET']}")
        else:
            print(f"Archived files ({len(archived_files)}):")
            for archived_file in archived_files[:10]:  # Show first 10
                print(f"  {archived_file}")
            if len(archived_files) > 10:
                print(f"  ... and {len(archived_files) - 10} more")
            
            if input(f"\n{COLORS['YELLOW']}Delete all archived files? (y/n): {COLORS['RESET']}").lower() == 'y':
                import shutil
                try:
                    shutil.rmtree(archive_dir)
                    print(f"{COLORS['GREEN']}Archive directory cleaned{COLORS['RESET']}")
                except Exception as e:
                    print(f"{COLORS['RED']}Failed to clean archive: {e}{COLORS['RESET']}")
    
    elif choice == "4":
        print(f"\n{COLORS['BLUE']}Current Log Files:{COLORS['RESET']}")
        if log_files:
            for log_file in log_files:
                file_path = os.path.join(logs_dir, log_file)
                size = os.path.getsize(file_path)
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  {log_file} ({size} bytes, modified: {mtime})")
        else:
            print(f"  No log files found")
        
        print(f"\n{COLORS['BLUE']}Deployment Info Files:{COLORS['RESET']}")
        if info_files:
            for info_file in info_files:
                file_path = os.path.join(logs_dir, info_file)
                mtime = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  {info_file} (modified: {mtime})")
        else:
            print(f"  No info files found")
        
        if archived_files:
            print(f"\n{COLORS['BLUE']}Archived Files ({len(archived_files)} total):{COLORS['RESET']}")
            for archived_file in archived_files[:5]:  # Show first 5
                print(f"  {archived_file}")
            if len(archived_files) > 5:
                print(f"  ... and {len(archived_files) - 5} more in archive/")
    
    elif choice == "5":
        return
    else:
        print(f"\n{COLORS['RED']}Invalid option. Please try again.{COLORS['RESET']}")
    
    wait_for_input()

def list_deployments():
    """List active deployments"""
    print(f"\n{COLORS['BLUE']}Active Deployments{COLORS['RESET']}")
    
    import glob
    info_files = glob.glob("logs/deployment_info_*.txt")
    
    if not info_files:
        print(f"{COLORS['GREEN']}No active deployments found{COLORS['RESET']}")
    else:
        print(f"Found {len(info_files)} deployments:\n")
        
        for info_file in info_files:
            try:
                with open(info_file, 'r') as f:
                    lines = f.readlines()
                
                deployment_id = "unknown"
                provider = "unknown"
                domain = "unknown"
                status = "unknown"
                timestamp = "unknown"
                
                for line in lines:
                    line = line.strip()
                    if line.startswith("Deployment ID:"):
                        deployment_id = line.split(": ", 1)[1]
                    elif line.startswith("Provider:"):
                        provider = line.split(": ", 1)[1]
                    elif line.startswith("Domain:"):
                        domain = line.split(": ", 1)[1]
                    elif line.startswith("Status:"):
                        status = line.split(": ", 1)[1]
                    elif line.startswith("Timestamp:"):
                        timestamp = line.split(": ", 1)[1]
                
                status_color = COLORS['GREEN'] if status == 'SUCCESS' else COLORS['RED']
                print(f"  ID: {COLORS['CYAN']}{deployment_id}{COLORS['RESET']}")
                print(f"  Provider: {provider}")
                print(f"  Domain: {domain}")
                print(f"  Status: {status_color}{status}{COLORS['RESET']}")
                print(f"  Time: {timestamp}")
                print("-" * 40)
                
            except Exception as e:
                print(f"{COLORS['RED']}Error reading {info_file}: {e}{COLORS['RESET']}")
    
    wait_for_input()

def archive_logs_before_deployment():
    """Archive old logs before starting any deployment operation"""
    try:
        print(f"{COLORS['YELLOW']}Archiving old deployment logs...{COLORS['RESET']}")
        archive_old_logs()
        print(f"{COLORS['GREEN']}Log archiving completed{COLORS['RESET']}")
    except Exception as e:
        print(f"{COLORS['RED']}Warning: Failed to archive old logs: {e}{COLORS['RESET']}")

def show_usage():
    """Display usage information and examples"""
    print(f"{COLORS['WHITE']}C2itall - Modular Red Team Infrastructure Deployment{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}================================================={COLORS['RESET']}")
    print()
    print(f"{COLORS['CYAN']}Usage:{COLORS['RESET']}")
    print(f"  python3 deploy.py                    # Interactive menu (default)")
    print(f"  python3 deploy.py --menu             # Interactive menu")
    print(f"  python3 deploy.py --auto-teardown    # Enable auto-teardown on failure")
    print()
    print(f"{COLORS['CYAN']}Options:{COLORS['RESET']}")
    print(f"  --auto-teardown    Automatically cleanup failed deployments without prompting")
    print(f"                     Useful for testing, overnight runs, or automated scenarios")
    print(f"  --menu             Start interactive menu (default behavior)")
    print()
    print(f"{COLORS['CYAN']}Examples:{COLORS['RESET']}")
    print(f"  # Normal interactive deployment")
    print(f"  python3 deploy.py")
    print()
    print(f"  # Testing deployment with auto-cleanup on failure")
    print(f"  python3 deploy.py --auto-teardown")
    print()
    print(f"{COLORS['YELLOW']}Auto-teardown Feature:{COLORS['RESET']}")
    print(f"  • When enabled, failed deployments are automatically cleaned up")
    print(f"  • No user prompt - resources are immediately torn down on failure")
    print(f"  • Useful for testing, overnight runs, or CI/CD scenarios")
    print(f"  • Can be enabled globally via --auto-teardown flag")
    print(f"  • Can be enabled per-deployment during interactive setup")
    print()

if __name__ == "__main__":
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description="C2itall - Modular red team infrastructure deployment")
        parser.add_argument('--auto-teardown', action='store_true', 
                          help='Enable automatic teardown on deployment failure (for testing/overnight runs)')
        parser.add_argument('--menu', action='store_true', default=True,
                          help='Start interactive menu (default)')
        parser.add_argument('--help-examples', action='store_true',
                          help='Show usage examples and detailed help')
        
        args = parser.parse_args()
        
        # Show detailed help if requested
        if args.help_examples:
            show_usage()
            sys.exit(0)
        
        # Set global auto-teardown flag if specified
        if args.auto_teardown:
            os.environ['C2ITALL_AUTO_TEARDOWN'] = 'true'
            print(f"{COLORS['YELLOW']}🔧 Auto-teardown enabled - failed deployments will be cleaned up automatically{COLORS['RESET']}")
        
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{COLORS['YELLOW']}Operation cancelled by user{COLORS['RESET']}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{COLORS['RED']}Unexpected error: {e}{COLORS['RESET']}")
        sys.exit(1)
