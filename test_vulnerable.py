import subprocess

user_input = input("Enter command: ")

command_map = {
    "whoami": ["whoami"],
    "hostname": ["hostname"],
}

if user_input in command_map:
    subprocess.call(command_map[user_input])
else:
    print("Command not allowed")