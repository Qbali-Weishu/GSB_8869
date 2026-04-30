#!/usr/bin/env python3
"""
系统安全审计 - 本地提权漏洞检测工具
用于检测系统中可能存在的本地提权漏洞，包括：
- SUID程序
- cron任务
- sudo配置缺陷
- 内核版本
"""

import argparse
import os
import pwd
import grp
import platform
import subprocess
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional


class PrivEscChecker:
    """本地提权漏洞检测类"""
    
    def __init__(self):
        self.results = {
            'suid': [],
            'cron': [],
            'sudo': [],
            'kernel': [],
            'writable': []
        }
        
        # 检测操作系统类型
        self.os_type = self._detect_os()
        print(f"[*] 检测到操作系统: {self.os_type}")
        
        # 危险的SUID程序列表
        self.dangerous_suid = [
            'nmap', 'vim', 'vi', 'less', 'more', 'head', 'tail',
            'cp', 'mv', 'rm', 'chmod', 'chown', 'dd', 'env',
            'find', 'gawk', 'perl', 'python', 'python3', 'ruby',
            'lua', 'bash', 'sh', 'dash', 'zsh', 'csh', 'tcsh',
            'nc', 'netcat', 'ncat', 'socat', 'telnet',
            'ftp', 'tftp', 'ssh', 'scp', 'rsync',
            'awk', 'grep', 'sed', 'ed', 'ex',
            'mount', 'umount', 'tar', 'cpio', 'ar',
            'pico', 'nano', 'emacs',
            'su', 'sudo', 'pkexec', 'doas'
        ]
        
        # 根据操作系统设置不同的目录
        if self.os_type == 'linux':
            # Linux系统目录
            self.suid_dirs = [
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/usr/local/bin', '/usr/local/sbin',
                '/opt', '/usr/gnu/bin'
            ]
            
            self.system_dirs = [
                '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/usr/lib', '/usr/lib64', '/lib', '/lib64',
                '/var/spool/cron', '/etc/cron.d', '/etc/cron.daily',
                '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly',
                '/boot', '/root', '/home'
            ]
            
            self.cron_dirs = [
                '/etc/crontab',
                '/etc/cron.d',
                '/etc/cron.daily',
                '/etc/cron.hourly',
                '/etc/cron.weekly',
                '/etc/cron.monthly',
                '/var/spool/cron',
                '/var/spool/cron/crontabs'
            ]
            
            self.sudoers_path = '/etc/sudoers'
            self.sudoers_d_path = '/etc/sudoers.d'
            
        elif self.os_type == 'macos':
            # macOS系统目录
            self.suid_dirs = [
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/usr/local/bin', '/usr/local/sbin',
                '/opt', '/Applications'
            ]
            
            self.system_dirs = [
                '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/usr/lib', '/Library', '/System',
                '/var/at/tabs', '/Library/LaunchDaemons',
                '/private/etc', '/private/var',
                '/Users', '/Volumes'
            ]
            
            self.cron_dirs = [
                '/etc/crontab',
                '/etc/cron.d',
                '/usr/lib/cron/tabs',
                '/var/at/tabs',
                '/Library/LaunchDaemons',
                '/Library/LaunchAgents'
            ]
            
            self.sudoers_path = '/etc/sudoers'
            self.sudoers_d_path = '/etc/sudoers.d'
            
        else:
            # 未知系统，使用默认值
            self.suid_dirs = [
                '/bin', '/sbin', '/usr/bin', '/usr/sbin',
                '/usr/local/bin', '/usr/local/sbin'
            ]
            
            self.system_dirs = [
                '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/usr/lib', '/lib', '/var', '/root', '/home'
            ]
            
            self.cron_dirs = [
                '/etc/crontab',
                '/etc/cron.d',
                '/var/spool/cron'
            ]
            
            self.sudoers_path = '/etc/sudoers'
            self.sudoers_d_path = '/etc/sudoers.d'
        
        # 用于去重的集合
        self._checked_files = set()
    
    def _detect_os(self) -> str:
        """检测操作系统类型"""
        system = platform.system().lower()
        
        if system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'macos'
        else:
            return 'unknown'
    
    def check_suid(self) -> List[Dict[str, Any]]:
        """检查SUID程序"""
        print("[*] 检查SUID程序...")
        
        dangerous_found = []
        
        # 只检查常见的SUID目录，避免全盘扫描超时
        for suid_dir in self.suid_dirs:
            if not os.path.exists(suid_dir):
                continue
            
            try:
                # 使用find命令检查单个目录，设置较短超时
                result = subprocess.run(
                    ['find', suid_dir, '-perm', '-4000', '-type', 'f', '-exec', 'ls', '-la', '{}', ';'],
                    capture_output=True, text=True, timeout=10
                )
                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    if not line:
                        continue
                    
                    parts = line.split()
                    if len(parts) < 9:
                        continue
                    
                    permissions = parts[0]
                    owner = parts[2]
                    file_path = ' '.join(parts[8:])
                    
                    # 去重检查
                    if file_path in self._checked_files:
                        continue
                    self._checked_files.add(file_path)
                    
                    file_name = os.path.basename(file_path)
                    
                    # 检查是否是危险的SUID程序
                    if owner == 'root':
                        # 检查程序名是否在危险列表中
                        base_name = file_name.split('.')[0].lower()
                        
                        # 检查文件名是否匹配危险程序
                        is_dangerous = False
                        danger_type = None
                        
                        for dangerous in self.dangerous_suid:
                            # 完全精确匹配命令名
                            if base_name == dangerous:
                                is_dangerous = True
                                danger_type = dangerous
                                break
                        
                        # 检查是否有写入权限
                        has_write_perm = False
                        if permissions[2] == 'w' or permissions[5] == 'w' or permissions[8] == 'w':
                            has_write_perm = True
                            is_dangerous = True
                        
                        if is_dangerous:
                            dangerous_found.append({
                                'path': file_path,
                                'permissions': permissions,
                                'owner': owner,
                                'danger_type': danger_type,
                                'has_write_perm': has_write_perm,
                                'description': self._get_suid_description(file_name, danger_type)
                            })
                            
            except Exception as e:
                print(f"[-] 检查目录 {suid_dir} 失败: {e}")
                continue
        
        self.results['suid'] = dangerous_found
        return dangerous_found
    
    def _get_suid_description(self, file_name: str, danger_type: str) -> str:
        """获取SUID程序的漏洞描述"""
        descriptions = {
            'nmap': "nmap可通过--interactive模式执行命令，SUID权限可提权至root",
            'vim': "vim可通过:!command执行命令，SUID权限可提权至root",
            'vi': "vi可通过:!command执行命令，SUID权限可提权至root",
            'less': "less可通过!command执行命令，SUID权限可提权至root",
            'more': "more可通过!command执行命令，SUID权限可提权至root",
            'bash': "bash SUID权限可直接获取root shell",
            'sh': "sh SUID权限可直接获取root shell",
            'python': "python可执行系统命令，SUID权限可提权至root",
            'python3': "python3可执行系统命令，SUID权限可提权至root",
            'perl': "perl可执行系统命令，SUID权限可提权至root",
            'ruby': "ruby可执行系统命令，SUID权限可提权至root",
            'find': "find可通过-exec参数执行命令，SUID权限可提权至root",
            'awk': "awk可通过system()执行命令，SUID权限可提权至root",
            'gawk': "gawk可通过system()执行命令，SUID权限可提权至root",
            'sed': "sed可通过e参数执行命令，SUID权限可提权至root",
            'cp': "cp可覆盖系统文件，SUID权限可提权至root",
            'mv': "mv可移动系统文件，SUID权限可提权至root",
            'rm': "rm可删除系统文件，SUID权限可提权至root",
            'chmod': "chmod可修改文件权限，SUID权限可提权至root",
            'chown': "chown可修改文件所有者，SUID权限可提权至root",
            'dd': "dd可修改系统文件，SUID权限可提权至root",
            'env': "env可执行命令，SUID权限可提权至root",
            'tar': "tar可通过--checkpoint-action执行命令，SUID权限可提权",
            'nc': "netcat可建立连接执行命令，SUID权限可提权至root",
            'netcat': "netcat可建立连接执行命令，SUID权限可提权至root",
            'socat': "socat可建立连接执行命令，SUID权限可提权至root",
            'ssh': "ssh可执行远程命令，SUID权限可提权至root",
            'scp': "scp可传输文件，SUID权限可提权至root",
            'rsync': "rsync可同步文件，SUID权限可提权至root",
            'mount': "mount可挂载文件系统，SUID权限可提权至root",
            'umount': "umount可卸载文件系统，SUID权限可提权至root",
            'su': "su用于切换用户，SUID是正常的，但配置不当可被利用",
            'sudo': "sudo用于特权执行，SUID是正常的，但配置不当可被利用"
        }
        
        if danger_type in descriptions:
            return descriptions[danger_type]
        
        return f"{file_name} 具有SUID权限，需要进一步检查是否存在已知漏洞"
    
    def check_cron(self) -> List[Dict[str, Any]]:
        """检查cron任务"""
        print("[*] 检查cron任务...")
        
        cron_issues = []
        # 用于去重的集合 - 存储问题的唯一标识
        seen_issues = set()
        
        for cron_dir in self.cron_dirs:
            if not os.path.exists(cron_dir):
                continue
            
            if os.path.isfile(cron_dir):
                # 单个文件
                issues = self._check_cron_file(cron_dir)
                for issue in issues:
                    # 创建唯一标识：文件路径 + 问题类型 + 命令（如果有）
                    issue_key = f"{issue['path']}:{issue['issue']}:{issue.get('command', '')}"
                    if issue_key not in seen_issues:
                        seen_issues.add(issue_key)
                        cron_issues.append(issue)
            elif os.path.isdir(cron_dir):
                # 目录，递归检查
                for root, dirs, files in os.walk(cron_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # 去重检查
                        if file_path in self._checked_files:
                            continue
                        self._checked_files.add(file_path)
                        
                        issues = self._check_cron_file(file_path)
                        for issue in issues:
                            issue_key = f"{issue['path']}:{issue['issue']}:{issue.get('command', '')}"
                            if issue_key not in seen_issues:
                                seen_issues.add(issue_key)
                                cron_issues.append(issue)
        
        self.results['cron'] = cron_issues
        return cron_issues
    
    def _check_cron_file(self, file_path: str) -> List[Dict[str, Any]]:
        """检查单个cron文件"""
        issues = []
        
        try:
            # 检查文件权限
            stat_info = os.stat(file_path)
            
            # 检查是否可写（非root用户可写）
            if (stat_info.st_mode & 0o002) or (stat_info.st_uid != 0):
                issues.append({
                    'path': file_path,
                    'issue': '可写的cron文件',
                    'permissions': oct(stat_info.st_mode)[-3:],
                    'owner': pwd.getpwuid(stat_info.st_uid).pw_name if stat_info.st_uid < 65534 else str(stat_info.st_uid),
                    'description': f"cron文件 {file_path} 可被非root用户写入，攻击者可替换定时任务提权"
                })
            
            # 读取文件内容
            with open(file_path, 'r') as f:
                content = f.read()
            
            # 检查是否有通配符（可能导致路径遍历）
            if '*' in content:
                # 检查是否有可利用的通配符（如tar命令等）
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('#') or not line:
                        continue
                    
                    # 检查是否包含危险命令和通配符
                    dangerous_cmds = ['tar', 'cpio', 'rsync', 'scp', 'zip', 'gzip']
                    for cmd in dangerous_cmds:
                        if cmd in line and '*' in line:
                            issues.append({
                                'path': file_path,
                                'issue': '包含通配符的cron任务',
                                'command': line,
                                'description': f"cron任务包含 {cmd} 命令和通配符，可能被利用进行路径遍历攻击"
                            })
            
            # 检查脚本路径
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                
                # 提取命令部分
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                # cron格式: min hour day mon dow user command
                # 或者: min hour day mon dow command (系统crontab)
                cmd_start = 5
                if parts[5] in ['root', 'www-data', 'apache', 'nginx', 'postgres', 'mysql']:
                    cmd_start = 6
                
                if cmd_start >= len(parts):
                    continue
                
                command = ' '.join(parts[cmd_start:])
                
                # 检查是否使用相对路径
                if not command.startswith('/') and not command.startswith('.'):
                    # 检查是否是绝对路径命令
                    first_word = command.split()[0] if command.split() else ''
                    if first_word and not first_word.startswith('/'):
                        # 检查PATH环境变量
                        issues.append({
                            'path': file_path,
                            'issue': '使用相对路径的cron任务',
                            'command': line,
                            'description': f"cron任务使用相对路径 {first_word}，可能被PATH劫持利用"
                        })
                
                # 检查可写的脚本
                # 提取脚本路径
                script_match = re.search(r'(/[\w/.-]+)', command)
                if script_match:
                    script_path = script_match.group(1)
                    if os.path.exists(script_path):
                        try:
                            script_stat = os.stat(script_path)
                            # 检查是否非root可写
                            if (script_stat.st_mode & 0o002) or (script_stat.st_uid != 0 and script_stat.st_mode & 0o020):
                                issues.append({
                                    'path': file_path,
                                    'issue': '可写的cron执行脚本',
                                    'script_path': script_path,
                                    'command': line,
                                    'description': f"cron任务执行的脚本 {script_path} 可被非root用户修改，攻击者可替换脚本提权"
                                })
                        except Exception:
                            pass
        
        except Exception as e:
            print(f"[-] 检查cron文件 {file_path} 失败: {e}")
        
        return issues
    
    def check_sudo(self) -> List[Dict[str, Any]]:
        """检查sudo配置"""
        print("[*] 检查sudo配置...")
        
        sudo_issues = []
        # 用于去重的集合
        seen_issues = set()
        
        # 检查sudoers文件
        if os.path.exists(self.sudoers_path):
            try:
                stat_info = os.stat(self.sudoers_path)
                # sudoers应该是root:root 0440
                if stat_info.st_mode != 0o100440:
                    issue_key = f"{self.sudoers_path}:sudoers文件权限错误"
                    if issue_key not in seen_issues:
                        seen_issues.add(issue_key)
                        sudo_issues.append({
                            'path': self.sudoers_path,
                            'issue': 'sudoers文件权限错误',
                            'permissions': oct(stat_info.st_mode)[-3:],
                            'expected': '0440 (root:root)',
                            'description': f"sudoers文件权限应为0440(root:root)，当前为{oct(stat_info.st_mode)[-3:]}，可能被篡改"
                        })
                
                if stat_info.st_uid != 0 or stat_info.st_gid != 0:
                    issue_key = f"{self.sudoers_path}:sudoers文件所有者错误"
                    if issue_key not in seen_issues:
                        seen_issues.add(issue_key)
                        owner_name = pwd.getpwuid(stat_info.st_uid).pw_name if stat_info.st_uid < 65534 else str(stat_info.st_uid)
                        group_name = grp.getgrgid(stat_info.st_gid).gr_name if stat_info.st_gid < 65534 else str(stat_info.st_gid)
                        sudo_issues.append({
                            'path': self.sudoers_path,
                            'issue': 'sudoers文件所有者错误',
                            'owner': f"{owner_name}:{group_name}",
                            'expected': 'root:root',
                            'description': f"sudoers文件所有者应为root:root，当前配置可能存在安全风险"
                        })
            except Exception as e:
                print(f"[-] 检查sudoers文件失败: {e}")
        
        # 检查sudoers.d目录
        if os.path.exists(self.sudoers_d_path):
            for root, dirs, files in os.walk(self.sudoers_d_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # 去重检查
                    if file_path in self._checked_files:
                        continue
                    self._checked_files.add(file_path)
                    
                    try:
                        stat_info = os.stat(file_path)
                        if stat_info.st_mode != 0o100440:
                            issue_key = f"{file_path}:sudoers.d配置文件权限错误"
                            if issue_key not in seen_issues:
                                seen_issues.add(issue_key)
                                sudo_issues.append({
                                    'path': file_path,
                                    'issue': 'sudoers.d配置文件权限错误',
                                    'permissions': oct(stat_info.st_mode)[-3:],
                                    'expected': '0440 (root:root)',
                                    'description': f"sudoers.d配置文件权限应为0440(root:root)，当前为{oct(stat_info.st_mode)[-3:]}"
                                })
                    except Exception:
                        pass
        
        # 检查当前用户的sudo权限
        try:
            # 尝试运行sudo -l
            result = subprocess.run(
                ['sudo', '-l', '-n'],
                capture_output=True, text=True, timeout=10
            )
            
            output = result.stdout + result.stderr
            
            # 检查是否有NOPASSWD配置
            if 'NOPASSWD:' in output:
                # 提取NOPASSWD的命令
                lines = output.split('\n')
                for line in lines:
                    if 'NOPASSWD:' in line:
                        # 提取命令
                        cmd_match = re.search(r'NOPASSWD:\s*(.*)', line)
                        if cmd_match:
                            commands = cmd_match.group(1).strip()
                            # 检查是否有危险命令
                            dangerous_cmds = ['ALL', 'bash', 'sh', 'su', 'sudo', 'vim', 'vi', 'nmap', 'python', 'perl', 'ruby']
                            for cmd in dangerous_cmds:
                                if cmd in commands.upper() or cmd in commands.lower():
                                    issue_key = f"sudo_nopasswd:{commands}"
                                    if issue_key not in seen_issues:
                                        seen_issues.add(issue_key)
                                        sudo_issues.append({
                                            'issue': '危险的sudo NOPASSWD配置',
                                            'command': commands,
                                            'description': f"当前用户配置了NOPASSWD: {commands}，无需密码即可执行特权命令，可直接提权"
                                        })
                                    break
            
            # 检查是否有ALL权限
            if 'ALL' in output and ('(ALL)' in output or '(root)' in output):
                if 'NOPASSWD:' not in output:
                    issue_key = "sudo_all权限配置"
                    if issue_key not in seen_issues:
                        seen_issues.add(issue_key)
                        sudo_issues.append({
                            'issue': 'sudo ALL权限配置',
                            'description': "当前用户具有sudo ALL权限，需密码但可能被暴力破解或社会工程利用"
                        })
        
        except Exception as e:
            print(f"[-] 检查sudo权限失败: {e}")
        
        # 检查sudoers文件内容（如果可读）
        try:
            if os.access(self.sudoers_path, os.R_OK):
                with open(self.sudoers_path, 'r') as f:
                    content = f.read()
                
                # 检查是否有危险配置
                dangerous_configs = [
                    (r'ALL\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL', '所有用户无需密码可执行所有命令'),
                    (r'\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s+/bin/bash', '用户可无需密码执行bash'),
                    (r'\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s+/bin/sh', '用户可无需密码执行sh'),
                    (r'\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s+/usr/bin/vim', '用户可无需密码执行vim'),
                    (r'\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s+/usr/bin/python', '用户可无需密码执行python'),
                    (r'\w+\s+ALL=\(ALL\)\s+NOPASSWD:\s+/usr/bin/nmap', '用户可无需密码执行nmap'),
                ]
                
                for pattern, desc in dangerous_configs:
                    matches = re.findall(pattern, content, re.MULTILINE)
                    for match in matches:
                        issue_key = f"{self.sudoers_path}:危险配置:{match}"
                        if issue_key not in seen_issues:
                            seen_issues.add(issue_key)
                            sudo_issues.append({
                                'path': self.sudoers_path,
                                'issue': '危险的sudoers配置',
                                'config': match,
                                'description': f"发现危险配置: {desc}"
                            })
        except Exception:
            pass
        
        self.results['sudo'] = sudo_issues
        return sudo_issues
    
    def check_kernel(self) -> List[Dict[str, Any]]:
        """检查内核版本"""
        print("[*] 检查内核版本...")
        
        kernel_issues = []
        
        # 获取内核信息
        kernel_version = platform.release()
        system_info = platform.platform()
        
        print(f"    系统版本: {system_info}")
        print(f"    内核版本: {kernel_version}")
        
        # 解析内核版本号
        # 格式通常为: 5.15.0-91-generic 或 4.18.0-425.19.2.el8_7.x86_64
        version_match = re.match(r'(\d+)\.(\d+)\.(\d+)', kernel_version)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            patch = int(version_match.group(3))
            
            # 检查已知的内核漏洞
            # 这里只检查一些常见的、影响较大的漏洞
            # 不依赖外部漏洞库，只检查本地版本
            
            # CVE-2022-0847 (DirtyPipe) - Linux 5.8-5.16.11/5.15.25/5.10.102
            if (major == 5 and minor >= 8) and (
                (minor < 16) or
                (minor == 16 and patch < 11) or
                (minor == 15 and patch < 25) or
                (minor == 10 and patch < 102)
            ):
                kernel_issues.append({
                    'cve': 'CVE-2022-0847 (DirtyPipe)',
                    'affected_versions': 'Linux 5.8 - 5.16.11/5.15.25/5.10.102',
                    'current_version': kernel_version,
                    'description': "DirtyPipe漏洞允许非特权用户写入任意只读文件，可导致本地提权",
                    'severity': '高'
                })
            
            # CVE-2021-4034 (PwnKit) - polkit漏洞
            # 这个是用户空间漏洞，但通常与内核版本相关
            # 检查是否是易受攻击的版本
            if major < 5 or (major == 5 and minor < 15):
                # 旧版本内核的系统可能运行易受攻击的polkit版本
                kernel_issues.append({
                    'cve': 'CVE-2021-4034 (PwnKit)',
                    'affected_versions': 'polkit版本 < 0.120',
                    'current_version': f"系统内核 {kernel_version} (需检查polkit版本)",
                    'description': "PwnKit漏洞允许非特权用户通过pkexec获取root权限",
                    'severity': '高'
                })
            
            # CVE-2021-3493 - overlayfs漏洞
            if major < 5 or (major == 5 and minor < 11):
                kernel_issues.append({
                    'cve': 'CVE-2021-3493',
                    'affected_versions': 'Linux < 5.11',
                    'current_version': kernel_version,
                    'description': "overlayfs漏洞允许非特权用户设置任意文件能力，可导致本地提权",
                    'severity': '高'
                })
            
            # CVE-2019-13272 - PTRACE_TRACEME漏洞
            if major < 5 or (major == 5 and minor < 2):
                kernel_issues.append({
                    'cve': 'CVE-2019-13272',
                    'affected_versions': 'Linux < 5.2',
                    'current_version': kernel_version,
                    'description': "PTRACE_TRACEME漏洞允许非特权用户获取root权限",
                    'severity': '高'
                })
        
        self.results['kernel'] = kernel_issues
        return kernel_issues
    
    def check_writable_dirs(self) -> List[Dict[str, Any]]:
        """检查可写的系统目录"""
        print("[*] 检查可写的系统目录...")
        
        writable_issues = []
        
        for directory in self.system_dirs:
            if not os.path.exists(directory):
                continue
            
            try:
                # 检查目录权限
                stat_info = os.stat(directory)
                
                # 检查是否可写（其他用户可写）
                is_writable = False
                write_type = []
                
                # 检查其他用户写权限
                if stat_info.st_mode & 0o002:
                    is_writable = True
                    write_type.append('其他用户可写')
                
                # 检查目录所有者不是root
                if stat_info.st_uid != 0:
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name if stat_info.st_uid < 65534 else str(stat_info.st_uid)
                    # 检查所有者是否有写权限
                    if stat_info.st_mode & 0o0200:
                        is_writable = True
                        write_type.append(f"所有者({owner})可写")
                
                # 检查组写权限
                if stat_info.st_mode & 0o0020:
                    group = grp.getgrgid(stat_info.st_gid).gr_name if stat_info.st_gid < 65534 else str(stat_info.st_gid)
                    is_writable = True
                    write_type.append(f"组({group})可写")
                
                if is_writable:
                    writable_issues.append({
                        'path': directory,
                        'permissions': oct(stat_info.st_mode)[-3:],
                        'owner': pwd.getpwuid(stat_info.st_uid).pw_name if stat_info.st_uid < 65534 else str(stat_info.st_uid),
                        'write_type': ', '.join(write_type),
                        'description': f"系统目录 {directory} 可被非root用户写入，攻击者可替换系统文件或修改配置提权"
                    })
            
            except Exception as e:
                print(f"[-] 检查目录 {directory} 失败: {e}")
        
        self.results['writable'] = writable_issues
        return writable_issues
    
    def generate_report(self) -> str:
        """生成检测报告"""
        print("\n" + "="*80)
        print("本地提权漏洞检测报告")
        print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
        
        report_lines = []
        report_lines.append("="*80)
        report_lines.append("本地提权漏洞检测报告")
        report_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("="*80)
        
        # 统计结果
        total_issues = sum(len(v) for v in self.results.values())
        
        if total_issues == 0:
            print("\n[+] 未发现明显的提权漏洞")
            report_lines.append("\n[+] 未发现明显的提权漏洞")
        else:
            print(f"\n[!] 共发现 {total_issues} 个潜在提权风险")
            report_lines.append(f"\n[!] 共发现 {total_issues} 个潜在提权风险")
            
            # SUID程序
            if self.results['suid']:
                print("\n" + "-"*80)
                print("SUID程序风险:")
                print("-"*80)
                report_lines.append("\n" + "-"*80)
                report_lines.append("SUID程序风险:")
                report_lines.append("-"*80)
                
                for i, issue in enumerate(self.results['suid'], 1):
                    print(f"\n[{i}] 路径: {issue['path']}")
                    print(f"    权限: {issue['permissions']}")
                    print(f"    所有者: {issue['owner']}")
                    if issue['danger_type']:
                        print(f"    危险类型: {issue['danger_type']}")
                    print(f"    描述: {issue['description']}")
                    
                    report_lines.append(f"\n[{i}] 路径: {issue['path']}")
                    report_lines.append(f"    权限: {issue['permissions']}")
                    report_lines.append(f"    所有者: {issue['owner']}")
                    if issue['danger_type']:
                        report_lines.append(f"    危险类型: {issue['danger_type']}")
                    report_lines.append(f"    描述: {issue['description']}")
            
            # Cron任务
            if self.results['cron']:
                print("\n" + "-"*80)
                print("Cron任务风险:")
                print("-"*80)
                report_lines.append("\n" + "-"*80)
                report_lines.append("Cron任务风险:")
                report_lines.append("-"*80)
                
                for i, issue in enumerate(self.results['cron'], 1):
                    print(f"\n[{i}] 问题: {issue['issue']}")
                    print(f"    文件: {issue['path']}")
                    if 'command' in issue:
                        print(f"    命令: {issue['command']}")
                    if 'permissions' in issue:
                        print(f"    权限: {issue['permissions']}")
                    print(f"    描述: {issue['description']}")
                    
                    report_lines.append(f"\n[{i}] 问题: {issue['issue']}")
                    report_lines.append(f"    文件: {issue['path']}")
                    if 'command' in issue:
                        report_lines.append(f"    命令: {issue['command']}")
                    if 'permissions' in issue:
                        report_lines.append(f"    权限: {issue['permissions']}")
                    report_lines.append(f"    描述: {issue['description']}")
            
            # Sudo配置
            if self.results['sudo']:
                print("\n" + "-"*80)
                print("Sudo配置风险:")
                print("-"*80)
                report_lines.append("\n" + "-"*80)
                report_lines.append("Sudo配置风险:")
                report_lines.append("-"*80)
                
                for i, issue in enumerate(self.results['sudo'], 1):
                    print(f"\n[{i}] 问题: {issue['issue']}")
                    if 'path' in issue:
                        print(f"    文件: {issue['path']}")
                    if 'config' in issue:
                        print(f"    配置: {issue['config']}")
                    if 'command' in issue:
                        print(f"    命令: {issue['command']}")
                    if 'permissions' in issue:
                        print(f"    权限: {issue['permissions']}")
                    print(f"    描述: {issue['description']}")
                    
                    report_lines.append(f"\n[{i}] 问题: {issue['issue']}")
                    if 'path' in issue:
                        report_lines.append(f"    文件: {issue['path']}")
                    if 'config' in issue:
                        report_lines.append(f"    配置: {issue['config']}")
                    if 'command' in issue:
                        report_lines.append(f"    命令: {issue['command']}")
                    if 'permissions' in issue:
                        report_lines.append(f"    权限: {issue['permissions']}")
                    report_lines.append(f"    描述: {issue['description']}")
            
            # 内核版本
            if self.results['kernel']:
                print("\n" + "-"*80)
                print("内核版本风险:")
                print("-"*80)
                report_lines.append("\n" + "-"*80)
                report_lines.append("内核版本风险:")
                report_lines.append("-"*80)
                
                for i, issue in enumerate(self.results['kernel'], 1):
                    if 'cve' in issue:
                        print(f"\n[{i}] CVE: {issue['cve']}")
                        print(f"    严重程度: {issue['severity']}")
                        print(f"    影响版本: {issue['affected_versions']}")
                        print(f"    当前版本: {issue['current_version']}")
                        print(f"    描述: {issue['description']}")
                        
                        report_lines.append(f"\n[{i}] CVE: {issue['cve']}")
                        report_lines.append(f"    严重程度: {issue['severity']}")
                        report_lines.append(f"    影响版本: {issue['affected_versions']}")
                        report_lines.append(f"    当前版本: {issue['current_version']}")
                        report_lines.append(f"    描述: {issue['description']}")
                    else:
                        print(f"\n[{i}] 问题: {issue['issue']}")
                        print(f"    描述: {issue['description']}")
                        
                        report_lines.append(f"\n[{i}] 问题: {issue['issue']}")
                        report_lines.append(f"    描述: {issue['description']}")
            
            # 可写目录
            if self.results['writable']:
                print("\n" + "-"*80)
                print("可写系统目录风险:")
                print("-"*80)
                report_lines.append("\n" + "-"*80)
                report_lines.append("可写系统目录风险:")
                report_lines.append("-"*80)
                
                for i, issue in enumerate(self.results['writable'], 1):
                    print(f"\n[{i}] 路径: {issue['path']}")
                    print(f"    权限: {issue['permissions']}")
                    print(f"    所有者: {issue['owner']}")
                    print(f"    写入方式: {issue['write_type']}")
                    print(f"    描述: {issue['description']}")
                    
                    report_lines.append(f"\n[{i}] 路径: {issue['path']}")
                    report_lines.append(f"    权限: {issue['permissions']}")
                    report_lines.append(f"    所有者: {issue['owner']}")
                    report_lines.append(f"    写入方式: {issue['write_type']}")
                    report_lines.append(f"    描述: {issue['description']}")
        
        # 提权建议
        print("\n" + "="*80)
        print("提权建议")
        print("="*80)
        report_lines.append("\n" + "="*80)
        report_lines.append("提权建议")
        report_lines.append("="*80)
        
        if self.results['suid']:
            print("\n[SUID提权建议]")
            print("- 对于危险的SUID程序，可尝试执行命令或读取敏感文件")
            print("- nmap: 使用 --interactive 模式")
            print("- vim: 使用 :!command 执行命令")
            print("- find: 使用 -exec 执行命令")
            print("- 参考: https://gtfobins.github.io/")
            
            report_lines.append("\n[SUID提权建议]")
            report_lines.append("- 对于危险的SUID程序，可尝试执行命令或读取敏感文件")
            report_lines.append("- nmap: 使用 --interactive 模式")
            report_lines.append("- vim: 使用 :!command 执行命令")
            report_lines.append("- find: 使用 -exec 执行命令")
            report_lines.append("- 参考: https://gtfobins.github.io/")
        
        if self.results['cron']:
            print("\n[Cron提权建议]")
            print("- 检查cron任务执行的脚本是否可写")
            print("- 如果脚本可写，替换为反弹shell或提权脚本")
            print("- 检查是否有通配符，可尝试路径遍历攻击")
            print("- 检查是否使用相对路径，可尝试PATH劫持")
            
            report_lines.append("\n[Cron提权建议]")
            report_lines.append("- 检查cron任务执行的脚本是否可写")
            report_lines.append("- 如果脚本可写，替换为反弹shell或提权脚本")
            report_lines.append("- 检查是否有通配符，可尝试路径遍历攻击")
            report_lines.append("- 检查是否使用相对路径，可尝试PATH劫持")
        
        if self.results['sudo']:
            print("\n[Sudo提权建议]")
            print("- 如果有NOPASSWD配置，直接使用sudo执行命令")
            print("- 检查可执行的命令是否可被利用")
            print("- 参考: https://gtfobins.github.io/#sudo")
            
            report_lines.append("\n[Sudo提权建议]")
            report_lines.append("- 如果有NOPASSWD配置，直接使用sudo执行命令")
            report_lines.append("- 检查可执行的命令是否可被利用")
            report_lines.append("- 参考: https://gtfobins.github.io/#sudo")
        
        if self.results['kernel']:
            print("\n[内核漏洞提权建议]")
            print("- 检查对应CVE的公开漏洞利用代码")
            print("- 确认系统是否有编译工具(gcc, make等)")
            print("- 尝试编译并执行漏洞利用代码")
            print("- 注意: 内核漏洞利用可能导致系统崩溃")
            
            report_lines.append("\n[内核漏洞提权建议]")
            report_lines.append("- 检查对应CVE的公开漏洞利用代码")
            report_lines.append("- 确认系统是否有编译工具(gcc, make等)")
            report_lines.append("- 尝试编译并执行漏洞利用代码")
            report_lines.append("- 注意: 内核漏洞利用可能导致系统崩溃")
        
        if self.results['writable']:
            print("\n[可写目录提权建议]")
            print("- 检查是否可替换系统文件或修改配置")
            print("- 尝试写入恶意库文件进行劫持")
            print("- 检查是否可修改cron任务或启动脚本")
            
            report_lines.append("\n[可写目录提权建议]")
            report_lines.append("- 检查是否可替换系统文件或修改配置")
            report_lines.append("- 尝试写入恶意库文件进行劫持")
            report_lines.append("- 检查是否可修改cron任务或启动脚本")
        
        print("\n" + "="*80)
        print("检测完成")
        print("="*80)
        
        report_lines.append("\n" + "="*80)
        report_lines.append("检测完成")
        report_lines.append("="*80)
        
        return '\n'.join(report_lines)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='系统安全审计 - 本地提权漏洞检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python3 privesc_checker.py --all          # 检查所有项
  python3 privesc_checker.py --suid         # 只检查SUID程序
  python3 privesc_checker.py --cron --sudo  # 检查cron和sudo
  python3 privesc_checker.py --output report.txt  # 保存报告到文件
        """
    )
    
    parser.add_argument('--all', action='store_true', help='检查所有项')
    parser.add_argument('--suid', action='store_true', help='检查SUID程序')
    parser.add_argument('--cron', action='store_true', help='检查cron任务')
    parser.add_argument('--sudo', action='store_true', help='检查sudo配置')
    parser.add_argument('--kernel', action='store_true', help='检查内核版本')
    parser.add_argument('--writable', action='store_true', help='检查可写系统目录')
    parser.add_argument('--output', '-o', type=str, help='保存报告到指定文件')
    parser.add_argument('--verbose', '-v', action='store_true', help='显示详细信息')
    
    args = parser.parse_args()
    
    # 如果没有指定任何检查项，默认检查所有
    if not (args.all or args.suid or args.cron or args.sudo or args.kernel or args.writable):
        args.all = True
    
    # 创建检查器
    checker = PrivEscChecker()
    
    print("\n" + "="*80)
    print("系统安全审计 - 本地提权漏洞检测工具")
    print("="*80 + "\n")
    
    # 执行检查
    if args.all or args.suid:
        checker.check_suid()
    
    if args.all or args.cron:
        checker.check_cron()
    
    if args.all or args.sudo:
        checker.check_sudo()
    
    if args.all or args.kernel:
        checker.check_kernel()
    
    if args.all or args.writable:
        checker.check_writable_dirs()
    
    # 生成报告
    report = checker.generate_report()
    
    # 保存报告
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n[+] 报告已保存到: {args.output}")
        except Exception as e:
            print(f"\n[-] 保存报告失败: {e}")


if __name__ == '__main__':
    main()
