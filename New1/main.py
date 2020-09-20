import os


def main():
    while True:
        role = input("Chces byt klient alebo server?\n\tc - klient\n\ts - server\n")
        if role == "c":
            os.system("py client.py")
            break
        if role == "s":
            os.system("py client.py")
            break
        print("Zly input\n")


if __name__ == "__main__":
    main()
