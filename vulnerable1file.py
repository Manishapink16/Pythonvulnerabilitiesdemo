import subprocess

def execute_command(command):
    subprocess.call(command, shell=True)

if __name__ == "__main__":
    user_input = input("Enter a command to execute: ")
    execute_command(user_input)
