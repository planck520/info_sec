# 字体文件

本目录存放离线字体文件（不提交 Git），打包时打入安装包。

## 需要下载的字体

从 Google Fonts 下载以下 `.woff2` 文件，放入本目录：

| 文件 | 下载地址 |
|------|---------|
| `Inter-Regular.woff2` | https://fonts.google.com/specimen/Inter — Regular 400 |
| `Inter-Medium.woff2`  | https://fonts.google.com/specimen/Inter — Medium 500 |
| `Inter-SemiBold.woff2` | https://fonts.google.com/specimen/Inter — SemiBold 600 |
| `JetBrainsMono-Regular.woff2` | https://fonts.google.com/specimen/JetBrains+Mono — Regular 400 |

## 备用方案

如果无法下载，CSS 会自动回退到系统字体：
- Inter → Segoe UI → system-ui → sans-serif
- JetBrains Mono → Cascadia Code → Consolas → monospace

## 打包注意事项

`build.py` 中需要将本目录作为 data_files 打入 PyInstaller 输出：
```
--add-data "frontend/assets/fonts;frontend/assets/fonts"
```
