# first we will import the subprocess module
import subprocess

# now we will store the profiles data in "data" variable by
# running the 1st cmd command using subprocess.check_output
data = subprocess.check_output(
    ['netsh', 'wlan', 'show', 'profiles']).decode('utf-8').split('\n')

# now we will store the profile by converting them to list
profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]

# using for loop in python we are checking and printing the wifi
# passwords if they are available using the 2nd cmd command
for i in profiles:
    # running the 2nd cmd command to check passwords
    results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i,
                                       'key=clear']).decode('utf-8').split('\n')
    # storing passwords after converting them to list
    results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
    # printing the profiles(wifi name) with their passwords using
    # try and except method
    try:
        print("{:<30}|  {:<}".format(i, results[0]))
    except IndexError:
        print("{:<30}|  {:<}".format(i, ""))
