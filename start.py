#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home 实时日志抓取工具 - 图形界面版本
支持IPv4和IPv6设备实时日志抓取与网址统计
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import json
import threading
import time
from collections import defaultdict
from urllib.parse import urlparse
import queue
import os
import configparser

class AdGuardLogGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AdGuard Home 实时日志抓取工具")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # 配置文件路径
        self.config_file = "adguard_config.ini"
        
        # AdGuard连接参数（从配置文件加载默认值）
        self.base_url = "http://192.168.100.1:8008"
        self.username = "root"
        self.password = "du13280325005"
        
        # 运行状态
        self.is_running = False
        self.session = None
        self.log_thread = None
        self.domain_count = defaultdict(int)
        self.client_ips = set()
        
        # 新增：只抓取被拦截日志的选项
        self.capture_blocked_only = tk.BooleanVar()
        self.capture_blocked_only.set(False)  # 默认不只抓取被拦截的日志
        
        # 创建UI
        self.create_widgets()
        
        # 加载配置
        self.load_config()
        
        # 消息队列用于线程间通信
        self.message_queue = queue.Queue()
        
        # 定期处理消息队列
        self.process_queue()
    
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # 标题
        title_label = ttk.Label(main_frame, text="AdGuard Home 实时日志抓取工具", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # AdGuard配置区域
        config_frame = ttk.LabelFrame(main_frame, text="AdGuard Home 配置", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)
        
        ttk.Label(config_frame, text="地址:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.url_entry = ttk.Entry(config_frame, width=20)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.url_entry.insert(0, self.base_url)
        
        ttk.Label(config_frame, text="用户名:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.username_entry = ttk.Entry(config_frame, width=15)
        self.username_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))
        self.username_entry.insert(0, self.username)
        
        ttk.Label(config_frame, text="密码:").grid(row=1, column=0, sticky="w", padx=(0, 5))
        self.password_entry = ttk.Entry(config_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10))
        self.password_entry.insert(0, self.password)
        
        # 客户端IP配置区域
        client_frame = ttk.LabelFrame(main_frame, text="客户端设备配置", padding="10")
        client_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        client_frame.columnconfigure(0, weight=1)
        client_frame.rowconfigure(1, weight=1)
        
        ttk.Label(client_frame, text="设备IP地址 (每行一个IP):").grid(row=0, column=0, sticky="w", padx=(0, 5))
        
        # 使用ScrolledText替代Entry，支持多行输入
        self.client_ip_text = scrolledtext.ScrolledText(client_frame, height=4)
        self.client_ip_text.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(5, 0))
        ttk.Label(client_frame, text="支持IPv4和IPv6，每行输入一个IP地址").grid(row=2, column=0, sticky="w")
        
        # 新增：只抓取被拦截日志的复选框
        blocked_checkbox = ttk.Checkbutton(client_frame, text="只抓取被拦截的日志", variable=self.capture_blocked_only)
        blocked_checkbox.grid(row=3, column=0, sticky="w", pady=(5, 0))
        
        # 控制按钮区域
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        self.start_button = ttk.Button(control_frame, text="开始抓取", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="停止抓取", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_button = ttk.Button(control_frame, text="保存结果", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(control_frame, text="清空统计", command=self.clear_stats)
        self.clear_button.pack(side=tk.LEFT)
        
        # 实时日志显示区域
        log_frame = ttk.LabelFrame(main_frame, text="实时日志", padding="5")
        log_frame.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(0, 10))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # 统计结果显示区域
        stats_frame = ttk.LabelFrame(main_frame, text="域名统计结果", padding="5")
        stats_frame.grid(row=5, column=0, columnspan=3, sticky="nsew")
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.rowconfigure(0, weight=1)
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=10)
        self.stats_text.grid(row=0, column=0, sticky="nsew")
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(10, 0))
    
    def load_config(self):
        """从配置文件加载设置"""
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            try:
                config.read(self.config_file, encoding='utf-8')
                if 'AdGuard' in config:
                    adguard_config = config['AdGuard']
                    self.base_url = adguard_config.get('url', self.base_url)
                    self.username = adguard_config.get('username', self.username)
                    self.password = adguard_config.get('password', self.password)
                
                # 加载客户端IP
                if 'Clients' in config:
                    clients_config = config['Clients']
                    client_ips = clients_config.get('ips', '')
                    if client_ips:
                        self.client_ip_text.delete("1.0", tk.END)
                        self.client_ip_text.insert("1.0", client_ips)
                
                # 加载域名统计
                if 'Stats' in config:
                    stats_config = config['Stats']
                    for key in stats_config:
                        try:
                            self.domain_count[key] = int(stats_config[key])
                        except ValueError:
                            pass  # 忽略无效的值
                    
                    # 更新显示
                    if self.domain_count:
                        self.update_stats_display()
                        self.status_var.set(f"已加载历史数据，共 {len(self.domain_count)} 个域名")
                
                # 新增：加载只抓取被拦截日志的选项
                if 'Options' in config:
                    options_config = config['Options']
                    capture_blocked = options_config.get('capture_blocked_only', 'False')
                    self.capture_blocked_only.set(capture_blocked.lower() == 'true')
                
                # 更新UI
                self.url_entry.delete(0, tk.END)
                self.url_entry.insert(0, self.base_url)
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, self.username)
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, self.password)
                
            except Exception as e:
                self.log_message(f"加载配置文件失败: {str(e)}")
    
    def save_config(self):
        """保存设置到配置文件"""
        config = configparser.ConfigParser()
        
        # 保存AdGuard配置
        config['AdGuard'] = {
            'url': self.url_entry.get().rstrip('/'),
            'username': self.username_entry.get(),
            'password': self.password_entry.get()
        }
        
        # 保存客户端IP
        client_ips_str = self.client_ip_text.get("1.0", tk.END).strip()
        config['Clients'] = {
            'ips': client_ips_str
        }
        
        # 保存域名统计
        config['Stats'] = {}
        for domain, count in self.domain_count.items():
            config['Stats'][domain] = str(count)
        
        # 新增：保存只抓取被拦截日志的选项
        config['Options'] = {
            'capture_blocked_only': str(self.capture_blocked_only.get())
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)
        except Exception as e:
            self.log_message(f"保存配置文件失败: {str(e)}")
    
    def log_message(self, message):
        """在日志区域添加消息"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_stats_display(self):
        """更新统计结果显示"""
        self.stats_text.delete(1.0, tk.END)
        sorted_domains = sorted(self.domain_count.items(), key=lambda x: x[1], reverse=True)
        
        for domain, count in sorted_domains:
            self.stats_text.insert(tk.END, f"{domain:<40} {count:>5} 次\n")
    
    def process_queue(self):
        """处理消息队列"""
        try:
            while True:
                message = self.message_queue.get_nowait()
                if message['type'] == 'log':
                    self.log_message(message['content'])
                elif message['type'] == 'stats':
                    self.update_stats_display()
                elif message['type'] == 'status':
                    self.status_var.set(message['content'])
        except queue.Empty:
            pass
        
        # 每100毫秒检查一次消息队列
        self.root.after(100, self.process_queue)
    
    def start_capture(self):
        """开始抓取日志"""
        # 保存当前配置
        self.save_config()
        
        # 获取配置
        self.base_url = self.url_entry.get().rstrip('/')
        self.username = self.username_entry.get()
        self.password = self.password_entry.get()
        
        # 获取客户端IP（从多行文本框中读取）
        client_ips_str = self.client_ip_text.get("1.0", tk.END)
        if not client_ips_str.strip():
            messagebox.showerror("错误", "请输入至少一个客户端IP地址")
            return
            
        # 按行分割并清理IP地址
        self.client_ips = set()
        for line in client_ips_str.split('\n'):
            ip = line.strip()
            if ip:  # 忽略空行
                self.client_ips.add(ip)
        
        # 初始化会话
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # 测试连接
        try:
            response = self.session.get(f"{self.base_url}/control/status", timeout=5)
            if response.status_code != 200:
                messagebox.showerror("连接失败", f"无法连接到AdGuard Home: {response.status_code}")
                return
        except Exception as e:
            messagebox.showerror("连接错误", f"连接AdGuard Home时出错: {str(e)}")
            return
        
        # 更新UI状态
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.is_running = True
        self.log_text.delete(1.0, tk.END)
        # 注意：不清空统计结果显示，保留历史数据
        
        # 启动日志抓取线程
        self.log_thread = threading.Thread(target=self.capture_logs, daemon=True)
        self.log_thread.start()
        
        # 显示当前模式
        mode_text = "只抓取被拦截日志" if self.capture_blocked_only.get() else "抓取所有日志"
        self.message_queue.put({'type': 'status', 'content': f'正在实时抓取日志 ({mode_text})...'})
        self.message_queue.put({'type': 'log', 'content': f'开始抓取设备 {", ".join(self.client_ips)} 的实时日志 ({mode_text})'})
    
    def stop_capture(self):
        """停止抓取日志"""
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        # 保存配置和统计数据
        self.save_config()
        
        self.message_queue.put({'type': 'status', 'content': f'已停止抓取，保留 {len(self.domain_count)} 条记录'})
        self.message_queue.put({'type': 'log', 'content': '已停止抓取日志，统计数据已保存'})
    
    def capture_logs(self):
        """实时抓取日志的线程函数"""
        last_processed_id = None
        
        while self.is_running:
            try:
                # 确保session存在
                if not self.session:
                    time.sleep(5)
                    continue
                    
                # 获取最新的日志条目
                params = {'limit': 50}  # 每次获取最新的50条
                response = self.session.get(f"{self.base_url}/control/querylog", params=params, timeout=10)
                
                if response.status_code == 200:
                    logs = response.json()
                    if 'data' in logs:
                        # 反向处理以按时间顺序处理
                        for entry in reversed(logs['data']):
                            # 检查是否已经处理过
                            entry_id = entry.get('id')
                            if last_processed_id and entry_id and entry_id <= last_processed_id:
                                continue
                            
                            # 检查是否是指定客户端的请求
                            client_ip = entry.get('client', '')
                            if client_ip in self.client_ips:
                                # 新增：检查是否只抓取被拦截的日志
                                if self.capture_blocked_only.get():
                                    # 检查是否有规则匹配（表示被拦截）
                                    rules = entry.get('rules', [])
                                    if not rules:  # 没有规则匹配，表示未被拦截
                                        continue  # 跳过这个条目
                                
                                domain = entry.get('question', {}).get('name', '').rstrip('.')
                                if domain:
                                    self.domain_count[domain] += 1
                                    
                                    # 添加到日志显示
                                    action = "拦截" if entry.get('rules', []) else "允许"
                                    self.message_queue.put({
                                        'type': 'log', 
                                        'content': f'[{client_ip}] {action}: {domain}'
                                    })
                                    
                                    # 更新统计显示
                                    self.message_queue.put({'type': 'stats', 'content': ''})
                            
                            # 更新最后处理的ID
                            if entry_id:
                                last_processed_id = entry_id
                
                # 等待一段时间再获取新日志
                time.sleep(2)
                
            except Exception as e:
                self.message_queue.put({
                    'type': 'log', 
                    'content': f'获取日志时出错: {str(e)}'
                })
                time.sleep(5)  # 出错时等待更长时间
    
    def save_results(self):
        """保存统计结果到文件"""
        if not self.domain_count:
            messagebox.showwarning("无数据", "没有可保存的统计数据")
            return
        
        # 选择保存文件路径
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="保存统计结果"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    sorted_domains = sorted(self.domain_count.items(), key=lambda x: x[1], reverse=True)
                    for domain, count in sorted_domains:
                        f.write(f"{domain} {count}\n")
                
                messagebox.showinfo("保存成功", f"统计结果已保存到:\n{filename}")
                self.message_queue.put({'type': 'log', 'content': f'统计结果已保存到: {filename}'})
                
                # 保存配置
                self.save_config()
            except Exception as e:
                messagebox.showerror("保存失败", f"保存文件时出错: {str(e)}")
    
    def clear_stats(self):
        """清空统计数据"""
        if messagebox.askyesno("确认清空", "确定要清空当前的统计结果吗？"):
            self.domain_count.clear()
            self.stats_text.delete(1.0, tk.END)
            self.message_queue.put({'type': 'log', 'content': '统计结果已清空'})
            
            # 保存配置
            self.save_config()

    def on_closing(self):
        """窗口关闭时的处理"""
        # 保存配置
        self.save_config()
        # 销毁窗口
        self.root.destroy()

def main():
    root = tk.Tk()
    app = AdGuardLogGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)  # 窗口关闭时保存配置并销毁窗口
    root.mainloop()

if __name__ == "__main__":
    main()