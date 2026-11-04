# win-sudo

Windows 版 sudo 实现

在 Windows 上实现类似 Linux 的 `sudo` 体验

## 功能

- 密码验证（3次尝试）
- 5分钟缓存
- 自动获取 SYSTEM / TrustedInstaller Token
- 自安装到 System32 并清理微软官方 sudo
- 支持以高权限运行任意命令

## 编译 (MSVC)

```bash
cl /EHsc /O2 sudo.cpp /link advapi32.lib user32.lib shell32.lib userenv.lib
```

## License

MIT
