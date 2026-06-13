"""
A3 Security System — OSINT CLI
"""

from osint_engine import OSINTEngine


def print_dict(data):
    for key, value in data.items():
        print(f"{key}: {value}")


def main():
    while True:
        print("\n==============================")
        print(" A3 OSINT Intelligence Module")
        print("==============================")
        print("[1] IP Intelligence")
        print("[2] Phone Metadata")
        print("[3] Username OSINT")
        print("[0] Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            ip = input("Enter IP address: ").strip()
            result = OSINTEngine.lookup_ip(ip)
            print("\n--- IP RESULT ---")
            print_dict(result)

        elif choice == "2":
            phone = input("Enter phone number with country code: ").strip()
            result = OSINTEngine.lookup_phone(phone)
            print("\n--- PHONE RESULT ---")
            print_dict(result)

        elif choice == "3":
            username = input("Enter username: ").strip()
            result = OSINTEngine.lookup_username(username)
            print("\n--- USERNAME RESULT ---")
            print_dict(result)

        elif choice == "0":
            print("Exiting OSINT module.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()