# AVB-XRay
Visualize and Compare Android Verified Boot Key Chains

中文文档：[`README.zh-CN.md`](README.zh-CN.md)

AVB-XRay is a Python utility that inspects Android AVB images (`vbmeta`, `vbmeta_system`, `boot`, `vendor_boot`, etc.) and compares their embedded public keys against multiple PEM private keys.

It helps you:

- Identify which key signs which image
- Detect chain partition relationships
- Understand which partitions are actually verified
- Recognize `Algorithm NONE` images and determine if they are still validated by a parent vbmeta
- Perform pre-signature validation before flashing

This tool is especially useful for:

- Custom ROM development
- AVB key migration
- Bootloader unlocking research
- Pre-sign verification workflows
- Reverse engineering vendor firmware

---

## Features

- Multi-PEM key comparison
- SHA1 + SHA256 public key fingerprint matching
- Chain partition descriptor parsing
- Full partition reference extraction from descriptors
- Intelligent `Algorithm NONE` interpretation
- Clear terminal output with semantic hints
- Interactive mode when started without arguments

---

## How It Works

### Private Key Side

For each provided PEM file, AVB-XRay:

1. Uses `avbtool extract_public_key`
2. Extracts the AVB public key
3. Calculates SHA1 and SHA256 fingerprints

### Image Side

For each provided image, AVB-XRay:

- Runs `avbtool info_image`
- Extracts:
  - Algorithm
  - Top-level public key
  - Chain partition keys
  - Referenced partitions in descriptors
- Matches discovered fingerprints against loaded PEM keys

---

## Requirements

- Python 3.8+
- `avbtool.py` in the same directory

You must place `avbtool.py` next to:

```
compare_avb_keys_multi.py
```

---

## Usage

Example:

```
python compare_avb_keys_multi.py \
  --key .\pem\testkey_rsa4096.pem \
  --key .\pem\testkey_rsa2048.pem \
  --vbmeta .\vbmeta_b.img \
  --vbmeta_system .\vbmeta_system_b.img \
  --boot .\boot_b.img \
  --image .\vendor_boot_b.img
```

If no arguments are provided, the script enters interactive mode and asks for PEM/image paths.

---

## Example Output

```
[vbmeta]
  Algorithm           : SHA256_RSA4096
  Top pubkey sha1     : 2597c2... -> testkey_rsa4096.pem
  -- Chain Partition keys --
  boot                sha1 : 2597c2... -> testkey_rsa4096.pem
  vbmeta_system       sha1 : cdbb77... -> testkey_rsa2048.pem
  Referenced partitions: boot, dtbo, vendor_boot, ...
```

---

## Understanding Algorithm NONE

If an image reports:

```
Algorithm : NONE
```

This does NOT automatically mean the image is unverified.

It means:

- The image does not contain its own signed vbmeta
- It may still be verified by a parent vbmeta via hash / hashtree descriptors

AVB-XRay helps you detect this by listing referenced partitions from descriptor blocks.

---

## Typical AVB Chain Example

Common structure:

```
vbmeta (RSA4096)
 ├── boot (RSA4096 chain)
 ├── vendor_boot (hash descriptor)
 └── vbmeta_system (RSA2048 chain)
        ├── system
        ├── product
        └── system_ext
```

AVB-XRay lets you see this clearly.

---

## Why This Tool Exists

When modifying:

- `system`
- `vendor_boot`
- `boot`
- `dtbo`
- or any partition under AVB enforcement

You need to know:

- Which vbmeta verifies it?
- Which key signs that vbmeta?
- Do you need to resign a parent image?

Guessing leads to brick.
This tool removes guesswork.

---

## Safety Notice

This tool does NOT modify images.
It only analyzes and reports.

You are responsible for flashing and signing decisions.

---

## License

MIT License

---

## Author

Built for Android reverse engineering and AVB research workflows.
