# AVB-XRay（中文说明）

AVB-XRay 是一个 Python 工具，用于分析 Android AVB 镜像（如 `vbmeta`、`vbmeta_system`、`boot`、`vendor_boot` 等），并将镜像中的公钥指纹与多个 PEM 私钥进行比对。

## 功能特性

- 多 PEM 对比
- SHA1 + SHA256 公钥指纹匹配
- Chain Partition descriptor 解析
- 提取 descriptor 中引用的分区列表
- 识别并解释 `Algorithm NONE`
- 支持命令行参数与交互模式

## 依赖

- Python 3.8+
- 与脚本同目录下的 `avbtool.py`

## 使用方式

### 1) 命令行模式

```bash
python compare_avb_keys_multi.py \
  --key ./pem/testkey_rsa4096.pem \
  --key ./pem/testkey_rsa2048.pem \
  --vbmeta ./vbmeta_b.img \
  --vbmeta_system ./vbmeta_system_b.img \
  --image ./vendor_boot_b.img \
  --image ./boot_b.img
```

说明：

- `--key` 可重复传入多个 PEM。
- `--image` 可重复传入任意镜像，脚本会根据文件名自动识别标签（支持 `_a` / `_b` 后缀）。
- 同时保留了 `--vbmeta`、`--vbmeta_system`、`--boot`、`--dtbo` 这类便捷参数。

### 2) 交互模式

如果启动时不传任何参数，脚本会自动进入交互模式：

1. 重复询问 `PEM（为空则下一步）`，并检查文件是否存在；
2. 再重复询问 `img（为空则下一步）`，并检查文件是否存在；
3. 处理完成后提示 `按任意键退出`。

## 输出说明

脚本会为每张镜像输出：

- `Algorithm`
- Top-level pubkey 的 SHA1/SHA256 与 PEM 匹配结果
- Chain Partition key 的 SHA1/SHA256 与 PEM 匹配结果
- `Referenced partitions`

当 `Algorithm` 为 `NONE` 时，表示该镜像自身不携带签名；是否被验证取决于上层 vbmeta 是否通过 descriptor 引用。

## 安全说明

本工具只做分析，不会修改镜像。

## 许可证

MIT
