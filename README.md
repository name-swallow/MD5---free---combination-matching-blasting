# MD5 brute-force cracking with arbitrary combinations
# Swallow MD5 Hash Cracker 🐦⚡

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Free-green)
![Multiprocessing](https://img.shields.io/badge/Threads-30~120-red)

一款基于多进程加速的MD5哈希碰撞破解工具，通过暴力枚举所有可能的字符组合快速匹配目标哈希值。

## 功能特性

- 🚀 多进程加速处理（最高支持120线程）
- 🔍 支持自定义字符集和密码长度范围
- 📊 实时进度显示（基于tqdm）
- ⚡ 智能批量处理（单次处理最高200万组合）
- 🛡️ 安全的中断处理（Ctrl+C立即停止）

## 安装使用

### 依赖环境
```bash
Python 3.8+ 
pip install tqdm
