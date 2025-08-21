#!/usr/bin/env python3
"""
Common naming utilities for C2itall deployments
Provides consistent naming options across all deployment types
"""

import os
import glob
from utils.common import COLORS

def get_existing_deployments():
    """Get list of existing deployments from deployment info files"""
    try:
        info_files = glob.glob("logs/deployment_info_*.txt")
        deployments = []
        
        for info_file in info_files:
            try:
                deployment_info = {}
                with open(info_file, 'r') as f:
                    lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if ": " in line and not line.startswith("-"):
                        parts = line.split(": ", 1)
                        if len(parts) == 2:
                            key, value = parts
                            deployment_info[key] = value
                
                if deployment_info.get('deployment_id'):
                    deployments.append(deployment_info)
            except Exception as e:
                continue  # Skip problematic files
        
        return deployments
    except Exception as e:
        return []

def select_deployment_for_naming(exclude_types=None, current_deployment_id=None):
    """
    Allow user to select an existing deployment to base naming on
    
    Args:
        exclude_types: List of deployment types to exclude (e.g., ['attack_box'])
        current_deployment_id: Current deployment ID to exclude from list
    """
    deployments = get_existing_deployments()
    
    if not deployments:
        print(f"{COLORS['YELLOW']}No existing deployments found{COLORS['RESET']}")
        return None
    
    print(f"\n{COLORS['CYAN']}Existing Deployments:{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}==================={COLORS['RESET']}")
    
    # Filter deployments based on criteria
    filtered_deployments = []
    for deployment in deployments:
        deployment_id = deployment.get('deployment_id', 'unknown')
        
        # Skip current deployment
        if current_deployment_id and deployment_id == current_deployment_id:
            continue
            
        # Skip excluded types
        deployment_type = deployment.get('deployment_type', 'unknown')
        if exclude_types and deployment_type in exclude_types:
            continue
            
        # Check if this is an attack box deployment (legacy check)
        is_attack_box = (
            deployment.get('deployment_type') == 'attack_box' or
            deployment.get('attack_box_deployment') == 'True' or
            deployment.get('attack_box_name')
        )
        
        if exclude_types and 'attack_box' in exclude_types and is_attack_box:
            continue
            
        filtered_deployments.append(deployment)
    
    if not filtered_deployments:
        print(f"{COLORS['YELLOW']}No suitable deployments found for naming{COLORS['RESET']}")
        return None
    
    # Display available deployments
    for i, deployment in enumerate(filtered_deployments, 1):
        deployment_id = deployment.get('deployment_id', 'unknown')
        provider = deployment.get('provider', 'unknown')
        domain = deployment.get('domain', 'N/A')
        deployment_type = deployment.get('deployment_type', 'unknown')
        
        print(f"{i}. {deployment_id}")
        print(f"   Type: {deployment_type}")
        print(f"   Provider: {provider}")
        print(f"   Domain: {domain}")
        
        # Show instance names if available
        instances = []
        if deployment.get('redirector_name'):
            instances.append(f"Redirector: {deployment.get('redirector_name')}")
        if deployment.get('c2_name'):
            instances.append(f"C2: {deployment.get('c2_name')}")
        if deployment.get('tracker_name'):
            instances.append(f"Tracker: {deployment.get('tracker_name')}")
        if deployment.get('attack_box_name'):
            instances.append(f"Attack Box: {deployment.get('attack_box_name')}")
        
        if instances:
            print(f"   Instances: {', '.join(instances)}")
        print()
    
    # Get user selection
    while True:
        try:
            choice = input(f"Select deployment (1-{len(filtered_deployments)}) or 'c' to cancel: ").strip()
            
            if choice.lower() == 'c':
                return None
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(filtered_deployments):
                selected = filtered_deployments[choice_num - 1]
                return selected.get('deployment_id')
            else:
                print(f"{COLORS['RED']}Invalid choice. Please try again.{COLORS['RESET']}")
        except ValueError:
            print(f"{COLORS['RED']}Invalid input. Please enter a number or 'c'.{COLORS['RESET']}")

def get_deployment_name_with_options(deployment_type, deployment_id, prefix="", existing_name=None):
    """
    Get deployment name with multiple naming options
    
    Args:
        deployment_type: Type of deployment (c2, redirector, tracker, attack_box, etc.)
        deployment_id: Current deployment ID
        prefix: Prefix for the name (e.g., 'r-', 'c-', 'a-', etc.)
        existing_name: Existing name if updating
    
    Returns:
        Chosen name for the deployment
    """
    
    print(f"\n{COLORS['BLUE']}{deployment_type.title()} Naming Options:{COLORS['RESET']}")
    print(f"1) Auto-generate name ({prefix}{deployment_id})")
    print(f"2) Name after existing deployment")
    print(f"3) Custom name")
    
    if existing_name:
        print(f"4) Keep current name ({existing_name})")
        default_choice = "4"
    else:
        default_choice = "1"
    
    naming_choice = input(f"Select naming option [{default_choice}]: ").strip() or default_choice
    
    if naming_choice == "1":
        # Auto-generate using deployment ID
        chosen_name = f"{prefix}{deployment_id}"
        print(f"Using auto-generated name: {COLORS['CYAN']}{chosen_name}{COLORS['RESET']}")
        
    elif naming_choice == "2":
        # Name after existing deployment
        # Exclude attack boxes when naming other types, but allow other types when naming attack boxes
        exclude_types = ['attack_box'] if deployment_type != 'attack_box' else []
        selected_deployment_id = select_deployment_for_naming(
            exclude_types=exclude_types, 
            current_deployment_id=deployment_id
        )
        
        if selected_deployment_id:
            chosen_name = f"{prefix}{selected_deployment_id}"
            print(f"{deployment_type.title()} will be named: {COLORS['CYAN']}{chosen_name}{COLORS['RESET']}")
            print(f"This associates it with deployment: {COLORS['YELLOW']}{selected_deployment_id}{COLORS['RESET']}")
        else:
            print(f"{COLORS['YELLOW']}No deployment selected, using auto-generated name{COLORS['RESET']}")
            chosen_name = f"{prefix}{deployment_id}"
            
    elif naming_choice == "3":
        # Custom name
        while True:
            custom_name = input(f"Enter custom {deployment_type} name: ").strip()
            if custom_name:
                # Ensure it starts with the correct prefix for consistency
                if prefix and not custom_name.startswith(prefix):
                    chosen_name = f"{prefix}{custom_name}"
                    print(f"Prefixed with '{prefix}': {COLORS['CYAN']}{chosen_name}{COLORS['RESET']}")
                else:
                    chosen_name = custom_name
                break
            else:
                print(f"{COLORS['RED']}Name cannot be empty. Please try again.{COLORS['RESET']}")
                
    elif naming_choice == "4" and existing_name:
        # Keep existing name
        chosen_name = existing_name
        print(f"Keeping current name: {COLORS['CYAN']}{chosen_name}{COLORS['RESET']}")
        
    else:
        # Default fallback
        print(f"{COLORS['YELLOW']}Invalid choice, using auto-generated name{COLORS['RESET']}")
        chosen_name = f"{prefix}{deployment_id}"
    
    return chosen_name

def show_naming_relationship(name, deployment_id, deployment_type):
    """Show the relationship between the chosen name and deployment"""
    if not name:
        return
        
    # Determine prefix based on deployment type
    prefix_map = {
        'redirector': 'r-',
        'c2': 's-',  # s for server
        'tracker': 't-',
        'attack_box': 'a-',
        'payload': 'p-'
    }
    
    expected_prefix = prefix_map.get(deployment_type, '')
    
    if expected_prefix and name.startswith(expected_prefix):
        target_deployment = name[len(expected_prefix):]  # Remove prefix
        if target_deployment != deployment_id:
            return {
                'target_deployment': target_deployment,
                'relationship_text': f"Named after deployment: {target_deployment}",
                'purpose_text': f"This {deployment_type} supports the {target_deployment} engagement"
            }
    
    return None

def get_deployment_type_prefix(deployment_type):
    """Get the standard prefix for a deployment type"""
    prefix_map = {
        'redirector': 'r-',
        'c2': 's-',  # s for server
        'tracker': 't-',
        'attack_box': 'a-',
        'payload': 'p-',
        'phishing': 'p-'
    }
    return prefix_map.get(deployment_type, '')
