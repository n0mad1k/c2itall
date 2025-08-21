#!/usr/bin/env python3
"""
Name generation utility for c2itall deployments
Generates verb-animal names similar to FourEyes with shared deployment IDs
"""

import random
import os

def load_word_list(filename):
    """Load words from a text file, one word per line"""
    try:
        # Check if we have FourEyes word lists
        foureyes_path = "/home/n0mad1k/Tools/FourEyes"
        if os.path.exists(foureyes_path):
            file_path = os.path.join(foureyes_path, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    words = [line.strip().lower() for line in f if line.strip()]
                return [word for word in words if word]  # Remove empty strings
    except Exception:
        pass
    
    # Fallback word lists if FourEyes not available
    if 'verbs' in filename:
        return [
            "blazing", "soaring", "charging", "prowling", "hunting", "stalking", 
            "striking", "rushing", "dashing", "racing", "flying", "diving", 
            "leaping", "climbing", "sliding", "spinning", "rolling", "sneaking", 
            "roaming", "wandering", "running", "jumping", "swimming", "crawling",
            "fighting", "defending", "attacking", "scanning", "searching", "finding"
        ]
    else:  # animals
        return [
            "wolf", "eagle", "tiger", "falcon", "bear", "lion", "shark", "hawk",
            "panther", "cobra", "viper", "rhino", "bull", "fox", "raven", "crow",
            "spider", "scorpion", "mantis", "dragon", "phoenix", "griffin", 
            "badger", "wolverine", "lynx", "jaguar", "cheetah", "leopard"
        ]

def _generate_verb_animal():
    """Generate a verb-animal combination"""
    verbs = load_word_list('verbs.txt')
    animals = load_word_list('animals.txt')
    
    verb = random.choice(verbs)
    animal = random.choice(animals)
    return f"{verb}{animal}"

def generate_deployment_id():
    """Generate a deployment ID using verb-animal combination"""
    return _generate_verb_animal()

def generate_attack_box_name(deployment_id):
    """Generate attack box name with a- prefix using shared deployment ID"""
    return f"a-{deployment_id}"

def generate_redirector_name(deployment_id):
    """Generate redirector name with r- prefix using shared deployment ID"""
    return f"r-{deployment_id}"

def generate_c2_name(deployment_id):
    """Generate C2 server name with s- prefix using shared deployment ID"""
    return f"s-{deployment_id}"

def generate_phishing_name(deployment_id):
    """Generate phishing server name with p- prefix using shared deployment ID"""
    return f"p-{deployment_id}"

def generate_tracker_name(deployment_id):
    """Generate tracker name with t- prefix using shared deployment ID"""
    return f"t-{deployment_id}"

if __name__ == "__main__":
    # Test the name generation
    deployment_id = generate_deployment_id()
    print(f"Testing shared deployment ID: {deployment_id}")
    print(f"Attack Box: {generate_attack_box_name(deployment_id)}")
    print(f"Redirector: {generate_redirector_name(deployment_id)}")
    print(f"C2 Server: {generate_c2_name(deployment_id)}")
    print(f"Phishing: {generate_phishing_name(deployment_id)}")
    print(f"Tracker: {generate_tracker_name(deployment_id)}")
