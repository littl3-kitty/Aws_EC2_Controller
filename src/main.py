"""
애플리케이션 진입점
"""
import tkinter as tk
from src.ui.main_window import MainWindow


def main():
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
