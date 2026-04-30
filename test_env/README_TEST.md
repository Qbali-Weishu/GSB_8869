# 测试环境说明

本目录包含模拟的提权漏洞测试环境，用于测试privesc_checker.py工具。

## 包含的测试用例

### 1. SUID程序 (usr/bin/)
- vim: 模拟具有SUID权限的vim编辑器
- find: 模拟具有SUID权限的find命令
  注意: 实际设置SUID位需要root权限

### 2. 可写系统目录 (writable_etc/)
- 权限设置为777，模拟可被非root用户写入的系统目录

### 3. Cron任务漏洞 (etc/cron.d/test_backup)
- 使用相对路径: backup_script.sh (可能被PATH劫持)
- 使用tar和通配符: tar -czf /tmp/backup.tar.gz /var/www/* (可能被路径遍历利用)
- 执行可写目录下的脚本: /tmp/cleanup.sh (如果脚本可写，可替换为恶意代码)
- cron文件权限设置为777，可被任意用户修改

### 4. Sudo配置漏洞 (etc/sudoers 和 etc/sudoers.d/)
- ALL ALL=(ALL) NOPASSWD: ALL (所有用户无需密码执行所有命令)
- chenyingchao ALL=(ALL) NOPASSWD: /bin/bash (无需密码执行bash)
- chenyingchao ALL=(ALL) NOPASSWD: /usr/bin/vim (无需密码执行vim)
- chenyingchao ALL=(ALL) NOPASSWD: /usr/bin/python3 (无需密码执行python)
- sudoers文件权限设置不当

## 测试方法

1. 运行 `python3 privesc_checker.py --all` 检查真实系统
2. 由于测试环境是模拟的，需要修改privesc_checker.py中的路径来测试
   或者手动检查这些模拟文件的配置是否符合预期

## 实际系统测试建议

要在真实系统上测试，可以：
1. 创建一个普通用户，给其配置危险的sudo权限（需要root）
2. 创建一个具有SUID权限的危险程序（需要root）
3. 修改系统目录权限为可写（需要root，谨慎操作）
4. 添加有问题的cron任务
