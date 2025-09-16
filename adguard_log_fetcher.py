#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home 自定义设备日志抓取工具
支持IPv4和IPv6设备日志抓取与网址统计
"""

import requests
import json
import sys
from collections import defaultdict
from urllib.parse import urlparse
import argparse

class AdGuardLogFetcher:
    def __init__(self, base_url, username, password):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def login(self):
        """登录到AdGuard Home"""
        try:
            response = self.session.get(f"{self.base_url}/control/status", timeout=10)
            if response.status_code == 200:
                print("✅ 成功连接到 AdGuard Home")
                return True
            else:
                print(f"❌ 连接失败: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ 连接错误: {str(e)}")
            return False
    
    def get_query_log(self, limit=1000):
        """获取查询日志"""
        try:
            params = {
                'limit': limit
            }
            response = self.session.get(f"{self.base_url}/control/querylog", params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"❌ 获取日志失败: {response.status_code}")
                return None
        except Exception as e:
            print(f"❌ 获取日志错误: {str(e)}")
            return None
    
    def filter_logs_by_client(self, logs, client_ips):
        """根据客户端IP地址过滤日志"""
        if not logs or 'data' not in logs:
            return []
        
        filtered_logs = []
        for entry in logs['data']:
            client_ip = entry.get('client', '')
            if client_ip in client_ips:
                filtered_logs.append(entry)
        
        return filtered_logs
    
    def extract_domains_and_count(self, logs):
        """提取域名并统计出现次数"""
        domain_count = defaultdict(int)
        
        for entry in logs:
            domain = entry.get('question', {}).get('name', '')
            if domain:
                # 移除末尾的点
                domain = domain.rstrip('.')
                domain_count[domain] += 1
        
        return dict(domain_count)
    
    def save_to_txt(self, domain_count, filename="domain_stats.txt"):
        """保存结果到文本文件"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for domain, count in sorted(domain_count.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"{domain} {count}\n")
            print(f"✅ 结果已保存到 {filename}")
            return filename
        except Exception as e:
            print(f"❌ 保存文件失败: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='AdGuard Home 自定义设备日志抓取工具')
    parser.add_argument('--url', default='http://192.168.100.1:8008', help='AdGuard Home 地址')
    parser.add_argument('--username', default='root', help='用户名')
    parser.add_argument('--password', default='du13280325005', help='密码')
    parser.add_argument('--clients', required=True, help='客户端IP地址，多个用逗号分隔')
    parser.add_argument('--limit', type=int, default=1000, help='日志条数限制')
    parser.add_argument('--output', default='domain_stats.txt', help='输出文件名')
    
    args = parser.parse_args()
    
    # 解析客户端IP列表
    client_ips = [ip.strip() for ip in args.clients.split(',') if ip.strip()]
    if not client_ips:
        print("❌ 请提供有效的客户端IP地址")
        return
    
    print(f"🔍 开始抓取 AdGuard Home 日志...")
    print(f"🌐 AdGuard 地址: {args.url}")
    print(f"👤 用户名: {args.username}")
    print(f"💻 客户端IP: {', '.join(client_ips)}")
    
    # 创建抓取器实例
    fetcher = AdGuardLogFetcher(args.url, args.username, args.password)
    
    # 登录
    if not fetcher.login():
        return
    
    # 获取日志
    print("📥 正在获取查询日志...")
    logs = fetcher.get_query_log(args.limit)
    if not logs:
        return
    
    # 过滤日志
    print("FilterWhere 正在根据客户端IP过滤日志...")
    filtered_logs = fetcher.filter_logs_by_client(logs, client_ips)
    print(f"📊 过滤后得到 {len(filtered_logs)} 条记录")
    
    if not filtered_logs:
        print("⚠️  没有找到匹配的记录")
        return
    
    # 统计域名
    print("📈 正在统计域名出现次数...")
    domain_count = fetcher.extract_domains_and_count(filtered_logs)
    print(f"📋 共统计到 {len(domain_count)} 个不同域名")
    
    # 保存结果
    filename = fetcher.save_to_txt(domain_count, args.output)
    if filename:
        print(f"🎉 任务完成！结果文件: {filename}")
        print("\n📊 前10个访问最多的域名:")
        for i, (domain, count) in enumerate(sorted(domain_count.items(), key=lambda x: x[1], reverse=True)[:10], 1):
            print(f"  {i:2d}. {domain:<30} ({count} 次)")

if __name__ == "__main__":
    main()