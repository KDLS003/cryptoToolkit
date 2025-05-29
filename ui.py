from colorama import Fore, Style
import os
import time

class UI:
    """
    Handles all user interface, CLI, and menu logic for the Crypto Toolkit v2.0.
    """
    @staticmethod
    def clear_screen() -> None:
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def print_header() -> None:
        UI.clear_screen()
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"{Fore.CYAN}║{Style.BRIGHT}              CRYPTO TOOLKIT v2.0              {Fore.CYAN}║")
        print(f"{Fore.CYAN}{'='*50}")
        print(f"{Fore.CYAN}║{Style.BRIGHT}                    by YNK                     {Fore.CYAN}║")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")

    @staticmethod
    def print_success(message: str) -> None:
        print(f"\n{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_error(message: str) -> None:
        print(f"\n{Fore.RED}✗ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_info(message: str) -> None:
        print(f"\n{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_menu(menu_groups, sub_menus) -> None:
        print(f"\n{Fore.CYAN}Main Menu:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*50}")
        print(f"\n{Fore.YELLOW}0. Help / About{Style.RESET_ALL}")
        for key, label in menu_groups:
            print(f"{Fore.YELLOW}{key}. {label}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")

    @staticmethod
    def get_input(prompt: str, required: bool = True) -> str:
        while True:
            value = input(f"\n{Fore.GREEN}{prompt}{Style.RESET_ALL}").strip()
            if not required or value:
                return value
            UI.print_error("This field is required!")

    @staticmethod
    def print_section(title: str) -> None:
        print(f"\n{Fore.CYAN}{'═'*55}")
        print(f"{Fore.CYAN}{title.center(55)}")
        print(f"{Fore.CYAN}{'═'*55}{Style.RESET_ALL}")

    @staticmethod
    def print_subsection(subtitle: str) -> None:
        print(f"\n{Fore.YELLOW}{subtitle}{Style.RESET_ALL}")

    @staticmethod
    def print_instruction(text: str) -> None:
        print(f"  {Fore.YELLOW}{text}{Style.RESET_ALL}")

    @staticmethod
    def print_result(label: str, value: str) -> None:
        print(f"  {Fore.CYAN}{label}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")

    @staticmethod
    def print_success_block(message: str) -> None:
        print(f"\n{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_error_block(message: str) -> None:
        print(f"\n{Fore.RED}✗ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_info_block(message: str) -> None:
        print(f"\n{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

    @staticmethod
    def print_loading(message: str, duration: float = 1) -> None:
        print(f"\n{Fore.YELLOW}{message}", end='', flush=True)
        for _ in range(3):
            time.sleep(duration/3)
            print(".", end='', flush=True)
        print(f"{Style.RESET_ALL}")

    # Add other menu/printing/input functions as needed 