__author__ = "Milo"
__copyright__ = "Copyright 2024, lamMilo"
__email__ = "admin@ffcld.cloud"

import socket
import threading
import os
from urllib import request  # For downloading the background image
from queue import Queue
from PyQt5 import QtWidgets, QtGui, QtCore
import ipaddress

socket.setdefaulttimeout(0.25)

class PortScannerApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Argus")
        self.setGeometry(100, 100, 600, 450)  # Adjusted height for progress bar

        # Download and set background image
        local_image_path = "argus_background.jpg"
        self.download_image("https://fadedhd.xyz/IMG/Github/LamMilo/Argus-new.jpg", local_image_path)
        self.set_background_image(local_image_path)

        # Target Input
        self.target_label = QtWidgets.QLabel("Enter target (IP or domain):", self)
        self.target_label.setGeometry(20, 20, 200, 20)
        self.target_label.setStyleSheet("color: white;")

        self.target_input = QtWidgets.QLineEdit(self)
        self.target_input.setGeometry(20, 50, 400, 30)
        self.target_input.setStyleSheet("""
            background: transparent;
            color: white;
            border: 1px solid white;
        """)

        # Port Range Input
        self.port_label = QtWidgets.QLabel("Enter port range (e.g., 1-500):", self)
        self.port_label.setGeometry(20, 100, 200, 20)
        self.port_label.setStyleSheet("color: white;")

        self.port_input = QtWidgets.QLineEdit(self)
        self.port_input.setGeometry(20, 130, 200, 30)
        self.port_input.setStyleSheet("""
            background: transparent;
            color: white;
            border: 1px solid white;
        """)

        # Scan Button
        self.scan_button = QtWidgets.QPushButton("Start Scan", self)
        self.scan_button.setGeometry(450, 50, 100, 30)
        self.scan_button.setStyleSheet("""
            background-color: rgba(255, 255, 255, 0.3);
            color: white;
            border: 1px solid white;
        """)
        self.scan_button.clicked.connect(self.start_scan)

        # Output Area
        self.output_area = QtWidgets.QTextEdit(self)
        self.output_area.setGeometry(20, 180, 560, 180)
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("""
            background: transparent;
            color: white;
            border: 1px solid white;
        """)

        # Progress Bar
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setGeometry(20, 380, 560, 20)
        self.progress_bar.setStyleSheet("""
            background: transparent;
            color: white;
            border: 1px solid white;
        """)
        self.progress_bar.setValue(0)

        # Dark Mode Toggle
        self.dark_mode_toggle = QtWidgets.QCheckBox("Dark Mode", self)
        self.dark_mode_toggle.setGeometry(450, 130, 100, 30)
        self.dark_mode_toggle.setStyleSheet("color: white;")
        self.dark_mode_toggle.stateChanged.connect(self.toggle_dark_mode)

        self.threadpool = QtCore.QThreadPool()

    def set_background_image(self, image_path):
        palette = self.palette()
        background_image = QtGui.QPixmap(image_path)
        palette.setBrush(QtGui.QPalette.Window, QtGui.QBrush(background_image))
        self.setPalette(palette)

    def download_image(self, url, save_path):
        try:
            response = request.urlopen(url)
            with open(save_path, 'wb') as f:
                f.write(response.read())
        except Exception as e:
            print(f"Error downloading image: {e}")

    def start_scan(self):
        target = self.target_input.text().strip()
        port_range = self.port_input.text().strip()

        if not target:
            self.output_area.append("Please enter a target.")
            return

        try:
            # Validate IP or Domain
            ipaddress.ip_address(target)  # If it's a valid IP address
        except ValueError:
            # If it's not an IP, verify if it's a valid domain
            if not ("." in target and len(target.split(".")) > 1):
                self.output_area.append("Invalid target. Enter a valid IP or domain.")
                return

        if not port_range or '-' not in port_range:
            self.output_area.append("Please enter a valid port range (e.g., 1-500).")
            return

        try:
            start_port, end_port = map(int, port_range.split('-'))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except ValueError:
            self.output_area.append("Invalid port range. Ports must be between 1 and 65535.")
            return

        self.output_area.append(f"Starting scan on target: {target}")

        # Run WHOIS Lookup
        self.output_area.append("Performing WHOIS lookup...")
        whois_output = self.whois_lookup(target)
        self.output_area.append(whois_output)

        # Reset Progress Bar
        total_ports = end_port - start_port + 1
        self.progress_bar.setMaximum(total_ports)
        self.progress_bar.setValue(0)

        # Run Port Scan
        worker = PortScanWorker(target, start_port, end_port)
        worker.signals.result.connect(self.display_result)
        worker.signals.progress.connect(self.update_progress_bar)
        worker.signals.finished.connect(lambda: self.output_area.append("Scan complete."))
        self.threadpool.start(worker)

    def whois_lookup(self, target):
        try:
            output = os.popen(f"whois {target}").read()
            if not output.strip():
                return "WHOIS Lookup failed. No data found."
            return f"WHOIS Lookup Results:\n{output}"
        except Exception as e:
            return f"Error performing WHOIS lookup: {e}"

    def display_result(self, result):
        self.output_area.append(result)

    def update_progress_bar(self, value):
        self.progress_bar.setValue(value)

    def toggle_dark_mode(self):
        if self.dark_mode_toggle.isChecked():
            dark_stylesheet = """
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QTextEdit {
                background-color: #3c3f41;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QPushButton {
                background-color: #555555;
                color: #ffffff;
                border: none;
            }
            QPushButton:hover {
                background-color: #666666;
            }
            QCheckBox {
                color: #ffffff;
            }
            """
            self.setStyleSheet(dark_stylesheet)
        else:
            self.setStyleSheet("")


class WorkerSignals(QtCore.QObject):
    result = QtCore.pyqtSignal(str)
    progress = QtCore.pyqtSignal(int)
    finished = QtCore.pyqtSignal()


class PortScanWorker(QtCore.QRunnable):
    def __init__(self, target, start_port, end_port):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.signals = WorkerSignals()

    def run(self):
        q = Queue()
        total_ports = self.end_port - self.start_port + 1
        scanned_ports = 0

        def portscan(port):
            nonlocal scanned_ports
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((self.target, port))
                self.signals.result.emit(f"Port {port} is open")
                s.close()
            except socket.gaierror:
                self.signals.result.emit("Error: Invalid target or network issue.")
                return
            except socket.timeout:
                pass  # Port is closed or filtered
            except Exception as e:
                self.signals.result.emit(f"Unexpected error on port {port}: {e}")
            finally:
                scanned_ports += 1
                self.signals.progress.emit(scanned_ports)

        def threader():
            while True:
                worker = q.get()
                portscan(worker)
                q.task_done()

        for x in range(50):
            t = threading.Thread(target=threader)
            t.daemon = True
            t.start()

        for port in range(self.start_port, self.end_port + 1):
            q.put(port)

        q.join()
        self.signals.finished.emit()


if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    main = PortScannerApp()
    main.show()
    sys.exit(app.exec_())
