# Stolen from stackoverflow


class bcolors:
    PURPLE = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def display(txt):
    print("[ ] " + txt)


def display_new(txt):
    txt = txt.replace("True", bcolors.BLUE + "True" + bcolors.GREEN)
    txt = txt.replace("False", bcolors.FAIL + "False" + bcolors.GREEN)
    print(bcolors.GREEN + "[+] " + txt + bcolors.ENDC)


def display_warning(txt):
    print(bcolors.WARNING + "[-] " + txt + bcolors.ENDC)


def display_error(txt):
    print(bcolors.FAIL + "[!] " + txt + bcolors.ENDC)
