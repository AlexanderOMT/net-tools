
import sys
import time
import multiprocessing
from multiprocessing import Value
class Spin:

    def __init__(self, message):
        self.message = message
        self.spin_thread = multiprocessing.Process(target=self.run_spin, args=() )


    def _spinning(self):
        symbols = '|/-\\'
        while True:
            for pointer in symbols:
                yield pointer


    def _show_spinning_on_left(self):
        my_spin = self._spinning()   
        try:
            while self.spin_thread.is_alive(): 
                line = f'\r {next(my_spin)} {self.message}... Ctrl + C to stop '
                sys.stdout.write(line)
                time.sleep(0.1)
                sys.stdout.flush()
        except KeyboardInterrupt:
            pass
        
    def run_spin(self):    
        
        self._show_spinning_on_left()
          

    def new_message(self, msg):
        # sys.stdout.write('\x1b[2K')
        self.message = msg

    def spin_alive(self):
        return self.spin_thread.is_alive()

    def start_spin(self):
        self.spin_thread.start() 

    def stop_spin(self):
        sys.stdout.flush()
        sys.stdout.write(f'\r[+] {self.message}   >>>  Done :D \n')
        self.spin_thread.terminate()
