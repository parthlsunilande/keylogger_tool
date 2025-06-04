import psutil  # Library for managing system processes
import time
from colorama import Fore, Style, init
from tqdm import tqdm  # For progress bar
import winsound  # For sound effects
from datetime import datetime

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Function to save logs
def save_log(content):
    with open("keylogger_detection_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()}: {content}\n")

# Function to list all running processes
def list_processes():
    print(f"{Fore.CYAN}{Style.BRIGHT}Listing all running processes...\n")
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            print(f"{Fore.YELLOW}Process ID: {proc.info['pid']}, Name: {proc.info['name']}")
        except psutil.AccessDenied:
            print(f"{Fore.RED}Access Denied for a process.")

# Function to detect suspicious processes (keyloggers)
def detect_keylogger():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Scanning for keyloggers...\n")
    suspicious_processes = []
    keywords = ['keylogger', 'logger', 'spy']  # List of keywords to detect suspicious processes

    for _ in tqdm(range(100), desc="Scanning Processes"):  # Simulate scanning with a progress bar
        time.sleep(0.01)  # Add a slight delay for the animation

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            # Check if the process name contains any of the suspicious keywords
            if any(keyword in proc.info['name'].lower() for keyword in keywords):
                suspicious_processes.append(proc.info)
        except psutil.AccessDenied:
            continue  # Skip processes that we can't access

    if suspicious_processes:
        print(f"\n{Fore.RED}{Style.BRIGHT}Suspicious processes detected:\n")
        for sp in suspicious_processes:
            print(f"{Fore.YELLOW}PID: {sp['pid']}, Name: {sp['name']}")
        save_log(f"Suspicious processes found: {suspicious_processes}")
        # Play alert sound
        winsound.Beep(1000, 500)
        return suspicious_processes
    else:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}No suspicious processes found.")
        save_log("No suspicious processes detected.")
        return None

# Function to terminate a suspicious process
def terminate_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"{Fore.GREEN}Process with PID {pid} terminated.")
        save_log(f"Terminated process with PID: {pid}")
    except Exception as e:
        print(f"{Fore.RED}Failed to terminate process: {e}")
        save_log(f"Failed to terminate process with PID {pid}: {e}")

# Main function to run the tool
if __name__ == "__main__":
    print(f"{Fore.MAGENTA}{Style.BRIGHT}Welcome to the Enhanced Keylogger Detection Tool!")
    print(f"{Fore.MAGENTA}-----------------------------------------------\n")

    list_processes()  # List all running processes
    suspicious_processes = detect_keylogger()  # Detect keyloggers

    if suspicious_processes:
        # Ask user if they want to terminate the suspicious processes
        terminate = input(f"\n{Fore.CYAN}Do you want to terminate these suspicious processes? (y/n): ").strip().lower()
        if terminate == 'y':
            print(f"{Fore.MAGENTA}{Style.BRIGHT}\nTerminating suspicious processes...\n")
            for process in suspicious_processes:
                terminate_process(process['pid'])  # Terminate each suspicious process
        else:
            print(f"{Fore.YELLOW}\nSuspicious processes were not terminated.")
    else:
        print(f"{Fore.GREEN}\nNo suspicious processes to terminate.")

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}Thank you for using the Enhanced Keylogger Detection Tool!")
