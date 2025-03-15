import itertools
import string
import multiprocessing
import queue
import signal
import sys
import hashlib
from tqdm import tqdm
import time
import datetime

def print_swallow():
    """打印程序的ASCII艺术标题"""
    SWALLOW_3D = r"""
       _____                      _   _                    
      / ____|                    | | | |                   
     | (___   __      __   __ _  | | | |   ___   __      __
      \___ \  \ \ /\ / /  / _` | | | | |  / _ \  \ \ /\ / /
      ____) |  \ V  V /  | (_| | | | | | | (_) |  \ V  V / 
     |_____/    \_/\_/    \__,_| |_| |_|  \___/    \_/\_/  
    """
    print(SWALLOW_3D)

def crack_worker(target_hash, chars, length_range, batch_size, progress_queue, result_queue, stop_event, update_threshold):
    """子进程工作函数，负责破解指定长度的密码"""
    for length in length_range:
        if stop_event.is_set():
            return
        password_iter = itertools.product(chars, repeat=length)
        progress_accumulator = 0
        while not stop_event.is_set():
            batch = list(itertools.islice(password_iter, batch_size))
            if not batch:
                break
            passwords = [''.join(p) for p in batch]
            hashes = [hashlib.md5(p.encode()).hexdigest() for p in passwords]
            if target_hash in hashes:
                index = hashes.index(target_hash)
                result_queue.put(passwords[index])
                stop_event.set()
                progress_queue.put(progress_accumulator + len(batch))
                return
            progress_accumulator += len(batch)
            if progress_accumulator >= update_threshold:
                progress_queue.put(progress_accumulator)
                progress_accumulator = 0
        if progress_accumulator > 0:
            progress_queue.put(progress_accumulator)

class PasswordCracker:
    def __init__(self, target_hash, chars, min_length, max_length, num_processes=30):
        """初始化密码破解器"""
        self.target_hash = target_hash.lower()  # 转换为小写以统一格式
        self.chars = list(dict.fromkeys(chars))  # 去重并保持顺序
        self.min_length = min_length
        self.max_length = max_length
        self.num_processes = min(num_processes, multiprocessing.cpu_count() * 2)  # 限制进程数
        if self.num_processes == 120:
            self.batch_size = 5000000 // self.num_processes  # ≈41666
            self.update_threshold = 5000000 // self.num_processes  # ≈41666
        else:
            self.batch_size = 1000000 // self.num_processes  # 默认30个进程时 ≈33333
            self.update_threshold = 1000000  # 每100万个组合更新
        self.start_time = None

    def crack(self):
        """执行密码破解"""
        signal.signal(signal.SIGINT, self._signal_handler)
        total_combinations = sum(len(self.chars) ** l for l in range(self.min_length, self.max_length + 1))
        self.start_time = time.time()

        manager = multiprocessing.Manager()
        progress_queue = manager.Queue()
        result_queue = manager.Queue()
        stop_event = manager.Event()

        lengths = list(range(self.min_length, self.max_length + 1))
        chunk_size = max(1, len(lengths) // self.num_processes)
        processes = []

        for i in range(self.num_processes):
            start_idx = i * chunk_size
            end_idx = start_idx + chunk_size if i < self.num_processes - 1 else len(lengths)
            if start_idx >= len(lengths):
                break
            length_range = lengths[start_idx:end_idx]
            p = multiprocessing.Process(
                target=crack_worker,
                args=(self.target_hash, self.chars, length_range, self.batch_size, progress_queue, result_queue, stop_event, self.update_threshold)
            )
            processes.append(p)
            p.start()

        completed = 0
        with tqdm(total=total_combinations, desc="Cracking Progress", dynamic_ncols=True) as pbar:
            while not stop_event.is_set():
                try:
                    increment = progress_queue.get(timeout=0.5)
                    completed += increment
                    pbar.update(increment)
                except queue.Empty:
                    pass

                if not result_queue.empty():
                    password = result_queue.get()
                    print(f"\nPassword found: {password}")
                    stop_event.set()
                    break

                elapsed_time = time.time() - self.start_time
                if completed > 0:
                    estimated_total_time = elapsed_time / completed * total_combinations
                    remaining_time = estimated_total_time - elapsed_time
                    pbar.set_postfix({
                        'Elapsed': str(datetime.timedelta(seconds=int(elapsed_time))),
                        'Remaining': str(datetime.timedelta(seconds=int(remaining_time)))
                    })

                if completed >= total_combinations:
                    break

        stop_event.set()
        for p in processes:
            p.terminate()
            p.join()

        elapsed_time = time.time() - self.start_time
        if stop_event.is_set() and not result_queue.empty():
            print(f"\nCracking completed successfully in {elapsed_time:.2f} seconds.")
        else:
            print(f"\nPassword not found within the given range. Took {elapsed_time:.2f} seconds.")

    def _signal_handler(self, sig, frame):
        """处理Ctrl+C信号"""
        print("\nStopping... Please wait.")
        sys.exit(0)

def get_valid_input(prompt, validation_func, error_msg):
    """循环获取用户输入，直到输入有效"""
    while True:
        try:
            value = input(prompt).strip()
            if validation_func(value):
                return value
            else:
                print(error_msg)
        except Exception as e:
            print(f"Invalid input: {e}. Please try again.")

def main():
    """主函数，处理用户输入并启动破解"""
    try:
        print_swallow()
        print("Welcome to the Password Cracker (MD5 Mode)!")

        min_length = int(get_valid_input(
            "Enter the minimum password length: ",
            lambda x: x.isdigit() and int(x) >= 1,
            "Minimum length must be at least 1"
        ))

        max_length = int(get_valid_input(
            "Enter the maximum password length: ",
            lambda x: x.isdigit() and int(x) >= min_length,
            f"Maximum length must be greater than or equal to {min_length}"
        ))

        chars = get_valid_input(
            "Enter the characters to use (press enter for default): ",
            lambda x: True,  # 允许空输入
            ""
        )
        if not chars:
            chars = string.printable.replace(' \t\n\r\x0b\x0c', '')
        chars = ''.join(sorted(set(chars)))  # 去重并排序
        print(f"Using characters: {chars}")

        target_hash = get_valid_input(
            "Enter the target MD5 hash: ",
            lambda x: len(x) == 32 and all(c in string.hexdigits for c in x),
            "Invalid MD5 hash. It must be a 32-character hexadecimal string."
        )

        num_processes = get_valid_input(
            "Enter the number of processes (default 30, max 120): ",
            lambda x: x == "" or (x.isdigit() and 1 <= int(x) <= 120),
            "Number of processes must be between 1 and 120"
        )
        num_processes = int(num_processes) if num_processes else 30

        cracker = PasswordCracker(target_hash, chars, min_length, max_length, num_processes)
        print(f"Using batch size: {cracker.batch_size} combinations per iteration.")
        cracker.crack()

    except KeyboardInterrupt:
        print("\nCracking interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()