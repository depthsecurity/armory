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


def display(txt, color=None, code="[ ] "):
    if color:
        txt = color + code + txt + bcolors.ENDC
    else:
        txt = code + txt
    try:
        print(txt)
    except:
        # Sometimes blocking errors occur. Don't know why. Just catching them here so the whole thing doesn't crash
        pass


def display_new(txt):
    txt = txt.replace("True", bcolors.BLUE + "True" + bcolors.GREEN)
    txt = txt.replace("False", bcolors.FAIL + "False" + bcolors.GREEN)
    display(txt, bcolors.GREEN, "[+] ")


def display_warning(txt):
    display(txt, bcolors.WARNING, "[-] ")


def display_error(txt):
    display(txt, bcolors.FAIL, "[!] ")

def display_purple(txt):
    display(txt, bcolors.PURPLE, "[*] ")