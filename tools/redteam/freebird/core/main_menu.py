# core/main_menu.py

from InquirerPy import inquirer
from core.utils import clear_screen
from core.config import config
from framework.reconnaissance.reconnaissance_menu import reconnaissance_menu  # Corrected path for Reconnaissance Menu

# Main Menu Function
def main_menu():
    while True:
        clear_screen()  # Clear screen before displaying the main menu
        selection = inquirer.select(
            message="Select a Tactic:",
            choices=[
                "Reconnaissance",
                "Initial Access",
                "Execution",
                "Persistence",
                "Privilege Escalation",
                "Defense Evasion",
                "Credential Access",
                "Discovery",
                "Lateral Movement",
                "Collection",
                "Command and Control",
                "Exfiltration",
                "Impact",
                "Resource Development",
                "Set Global Variable",
                "Show Global Variables",
                "Exit",
            ],
            qmark="",  # Remove question mark
            pointer="👾"  # Customize the pointer
        ).execute()

        # Call relevant function based on user selection
        if selection == "Exit":
            print("Exiting...")
            break
        elif selection == "Set Global Variable":
            config.prompt_set_variable()
        elif selection == "Show Global Variables":
            config.show_variables()
        elif selection == "Reconnaissance":
            reconnaissance_menu()  # Navigate to Reconnaissance Menu
        else:
            # Handle options under construction
            print("This feature is under construction. Returning to the main menu...")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main_menu()
