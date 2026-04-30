#!/usr/bin/env python3
"""
测试环境设置脚本
用于创建模拟的提权漏洞测试环境
"""

import os
import stat
import subprocess
import pwd
import grp


def setup_test_environment():
    """设置测试环境"""
    print("="*80)
    print("设置测试环境")
    print("="*80 + "\n")
    
    # 获取当前用户信息
    current_user = pwd.getpwuid(os.getuid())
    current_group = grp.getgrgid(os.getgid())
    
    print(f"当前用户: {current_user.pw_name}")
    print(f"当前组: {current_group.gr_name}")
    print()
    
    # 创建测试目录结构
    test_dir = os.path.join(os.getcwd(), 'test_env')
    
    if os.path.exists(test_dir):
        print(f"[*] 清理旧的测试环境...")
        import shutil
        shutil.rmtree(test_dir)
    
    print(f"[*] 创建测试目录结构...")
    
    # 创建模拟的系统目录
    mock_etc = os.path.join(test_dir, 'etc')
    mock_bin = os.path.join(test_dir, 'usr', 'bin')
    mock_cron_d = os.path.join(test_dir, 'etc', 'cron.d')
    mock_sudoers_d = os.path.join(test_dir, 'etc', 'sudoers.d')
    mock_var_spool = os.path.join(test_dir, 'var', 'spool', 'cron')
    
    os.makedirs(mock_etc, exist_ok=True)
    os.makedirs(mock_bin, exist_ok=True)
    os.makedirs(mock_cron_d, exist_ok=True)
    os.makedirs(mock_sudoers_d, exist_ok=True)
    os.makedirs(mock_var_spool, exist_ok=True)
    
    print(f"    创建目录: {mock_etc}")
    print(f"    创建目录: {mock_bin}")
    print(f"    创建目录: {mock_cron_d}")
    print(f"    创建目录: {mock_sudoers_d}")
    print(f"    创建目录: {mock_var_spool}")
    print()
    
    # 1. 创建危险的SUID程序（模拟）
    print("[*] 创建危险的SUID程序（模拟）...")
    
    # 创建一个模拟的vim程序
    mock_vim = os.path.join(mock_bin, 'vim')
    with open(mock_vim, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "This is a mock vim for testing SUID vulnerabilities"\n')
        f.write('echo "Real vim with SUID can be exploited via :!command"\n')
    
    # 设置权限
    os.chmod(mock_vim, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    # 尝试设置SUID位（可能需要root权限）
    try:
        os.chmod(mock_vim, stat.S_ISUID | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"    [成功] 创建SUID程序: {mock_vim} (权限: {oct(os.stat(mock_vim).st_mode)[-4:]})")
    except Exception as e:
        print(f"    [警告] 无法设置SUID位（需要root权限）: {e}")
        print(f"    [信息] 已创建文件但无SUID位: {mock_vim}")
    
    # 创建一个模拟的find程序
    mock_find = os.path.join(mock_bin, 'find')
    with open(mock_find, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "This is a mock find for testing SUID vulnerabilities"\n')
        f.write('echo "Real find with SUID can be exploited via -exec"\n')
    
    try:
        os.chmod(mock_find, stat.S_ISUID | stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        print(f"    [成功] 创建SUID程序: {mock_find} (权限: {oct(os.stat(mock_find).st_mode)[-4:]})")
    except Exception as e:
        print(f"    [警告] 无法设置SUID位（需要root权限）: {e}")
        print(f"    [信息] 已创建文件但无SUID位: {mock_find}")
    
    # 创建一个可写的"系统"目录
    print("\n[*] 创建可写的系统目录...")
    writable_dir = os.path.join(test_dir, 'writable_etc')
    os.makedirs(writable_dir, exist_ok=True)
    
    # 设置为其他用户可写
    os.chmod(writable_dir, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    print(f"    [成功] 创建可写目录: {writable_dir} (权限: {oct(os.stat(writable_dir).st_mode)[-4:]})")
    
    # 2. 创建有问题的cron任务
    print("\n[*] 创建有问题的cron任务...")
    
    # 创建一个cron文件，包含可利用的任务
    cron_file = os.path.join(mock_cron_d, 'test_backup')
    with open(cron_file, 'w') as f:
        f.write('# 测试用的cron任务 - 包含安全漏洞\n')
        f.write('# 漏洞1: 使用相对路径\n')
        f.write('*/5 * * * * root backup_script.sh\n')
        f.write('# 漏洞2: 使用tar和通配符（可能被路径遍历利用）\n')
        f.write('0 2 * * * root tar -czf /tmp/backup.tar.gz /var/www/*\n')
        f.write('# 漏洞3: 执行可写目录下的脚本\n')
        f.write('30 3 * * * root /tmp/cleanup.sh\n')
    
    # 设置为可写（模拟安全漏洞）
    os.chmod(cron_file, stat.S_IRWXU | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
    print(f"    [成功] 创建问题cron文件: {cron_file} (权限: {oct(os.stat(cron_file).st_mode)[-4:]})")
    
    # 创建一个可写的脚本（模拟cron执行的脚本）
    mock_cleanup = os.path.join(test_dir, 'tmp', 'cleanup.sh')
    os.makedirs(os.path.dirname(mock_cleanup), exist_ok=True)
    with open(mock_cleanup, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Cleaning up temporary files..."\n')
    
    # 设置为其他用户可写
    os.chmod(mock_cleanup, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    print(f"    [成功] 创建可写脚本: {mock_cleanup} (权限: {oct(os.stat(mock_cleanup).st_mode)[-4:]})")
    
    # 3. 创建有问题的sudo配置
    print("\n[*] 创建有问题的sudo配置...")
    
    # 创建一个sudoers文件（模拟）
    mock_sudoers = os.path.join(mock_etc, 'sudoers')
    with open(mock_sudoers, 'w') as f:
        f.write('# 测试用的sudoers文件 - 包含安全漏洞\n')
        f.write('# 漏洞1: 所有用户无需密码可执行所有命令\n')
        f.write('ALL ALL=(ALL) NOPASSWD: ALL\n')
        f.write('# 漏洞2: 特定用户无需密码执行bash\n')
        f.write(f'{current_user.pw_name} ALL=(ALL) NOPASSWD: /bin/bash\n')
        f.write('# 漏洞3: 特定用户无需密码执行vim\n')
        f.write(f'{current_user.pw_name} ALL=(ALL) NOPASSWD: /usr/bin/vim\n')
    
    # 设置权限（模拟错误配置 - 应该是0440，但设置为可写）
    os.chmod(mock_sudoers, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)
    print(f"    [成功] 创建问题sudoers文件: {mock_sudoers} (权限: {oct(os.stat(mock_sudoers).st_mode)[-4:]})")
    
    # 创建sudoers.d目录下的问题配置
    mock_sudoers_d_file = os.path.join(mock_sudoers_d, 'user_permissions')
    with open(mock_sudoers_d_file, 'w') as f:
        f.write('# 测试用的sudoers.d配置 - 包含安全漏洞\n')
        f.write('# 漏洞: 用户无需密码执行python\n')
        f.write(f'{current_user.pw_name} ALL=(ALL) NOPASSWD: /usr/bin/python3\n')
    
    os.chmod(mock_sudoers_d_file, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)
    print(f"    [成功] 创建问题sudoers.d文件: {mock_sudoers_d_file} (权限: {oct(os.stat(mock_sudoers_d_file).st_mode)[-4:]})")
    
    # 4. 创建测试说明
    print("\n[*] 创建测试说明...")
    readme_file = os.path.join(test_dir, 'README_TEST.md')
    with open(readme_file, 'w') as f:
        f.write('# 测试环境说明\n\n')
        f.write('本目录包含模拟的提权漏洞测试环境，用于测试privesc_checker.py工具。\n\n')
        f.write('## 包含的测试用例\n\n')
        f.write('### 1. SUID程序 (usr/bin/)\n')
        f.write('- vim: 模拟具有SUID权限的vim编辑器\n')
        f.write('- find: 模拟具有SUID权限的find命令\n')
        f.write('  注意: 实际设置SUID位需要root权限\n\n')
        
        f.write('### 2. 可写系统目录 (writable_etc/)\n')
        f.write('- 权限设置为777，模拟可被非root用户写入的系统目录\n\n')
        
        f.write('### 3. Cron任务漏洞 (etc/cron.d/test_backup)\n')
        f.write('- 使用相对路径: backup_script.sh (可能被PATH劫持)\n')
        f.write('- 使用tar和通配符: tar -czf /tmp/backup.tar.gz /var/www/* (可能被路径遍历利用)\n')
        f.write('- 执行可写目录下的脚本: /tmp/cleanup.sh (如果脚本可写，可替换为恶意代码)\n')
        f.write('- cron文件权限设置为777，可被任意用户修改\n\n')
        
        f.write('### 4. Sudo配置漏洞 (etc/sudoers 和 etc/sudoers.d/)\n')
        f.write('- ALL ALL=(ALL) NOPASSWD: ALL (所有用户无需密码执行所有命令)\n')
        f.write(f'- {current_user.pw_name} ALL=(ALL) NOPASSWD: /bin/bash (无需密码执行bash)\n')
        f.write(f'- {current_user.pw_name} ALL=(ALL) NOPASSWD: /usr/bin/vim (无需密码执行vim)\n')
        f.write(f'- {current_user.pw_name} ALL=(ALL) NOPASSWD: /usr/bin/python3 (无需密码执行python)\n')
        f.write('- sudoers文件权限设置不当\n\n')
        
        f.write('## 测试方法\n\n')
        f.write('1. 运行 `python3 privesc_checker.py --all` 检查真实系统\n')
        f.write('2. 由于测试环境是模拟的，需要修改privesc_checker.py中的路径来测试\n')
        f.write('   或者手动检查这些模拟文件的配置是否符合预期\n\n')
        
        f.write('## 实际系统测试建议\n\n')
        f.write('要在真实系统上测试，可以：\n')
        f.write('1. 创建一个普通用户，给其配置危险的sudo权限（需要root）\n')
        f.write('2. 创建一个具有SUID权限的危险程序（需要root）\n')
        f.write('3. 修改系统目录权限为可写（需要root，谨慎操作）\n')
        f.write('4. 添加有问题的cron任务\n')
    
    print(f"    [成功] 创建测试说明: {readme_file}")
    
    # 5. 创建一个专门用于测试的修改版检测脚本
    print("\n[*] 创建测试版检测脚本...")
    test_checker = os.path.join(test_dir, 'test_privesc_checker.py')
    
    # 读取原始脚本并修改路径
    with open('privesc_checker.py', 'r') as f:
        original_content = f.read()
    
    # 修改系统目录路径
    modified_content = original_content.replace(
        "        # 可写系统目录列表\n        self.system_dirs = [\n            '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',",
        f"        # 可写系统目录列表（测试版）\n        self.system_dirs = [\n            '{writable_dir}', '{mock_etc}', '{mock_bin}',"
    )
    
    # 修改cron目录路径
    modified_content = modified_content.replace(
        "        # 检查系统cron目录\n        cron_dirs = [\n            '/etc/crontab',\n            '/etc/cron.d',",
        f"        # 检查系统cron目录（测试版）\n        cron_dirs = [\n            '{cron_file}',\n            '{mock_cron_d}',"
    )
    
    # 修改sudoers路径
    modified_content = modified_content.replace(
        "        # 检查sudoers文件权限\n        sudoers_path = '/etc/sudoers'\n        sudoers_d_path = '/etc/sudoers.d'",
        f"        # 检查sudoers文件权限（测试版）\n        sudoers_path = '{mock_sudoers}'\n        sudoers_d_path = '{mock_sudoers_d}'"
    )
    
    with open(test_checker, 'w') as f:
        f.write(modified_content)
    
    os.chmod(test_checker, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
    print(f"    [成功] 创建测试版检测脚本: {test_checker}")
    
    print("\n" + "="*80)
    print("测试环境设置完成")
    print("="*80)
    print(f"\n测试环境位于: {test_dir}")
    print("\n测试用例:")
    print("  1. SUID程序 (需要root权限才能真正设置SUID位)")
    print("  2. 可写系统目录 (writable_etc/)")
    print("  3. 有问题的cron任务 (etc/cron.d/test_backup)")
    print("  4. 危险的sudo配置 (etc/sudoers, etc/sudoers.d/)")
    print("\n运行测试:")
    print(f"  cd {test_dir} && python3 test_privesc_checker.py --all")
    print("\n注意:")
    print("  - SUID位设置需要root权限，普通用户无法设置")
    print("  - 测试版脚本使用模拟路径进行测试")
    print("  - 真实系统测试需要root权限，谨慎操作")


if __name__ == '__main__':
    setup_test_environment()
