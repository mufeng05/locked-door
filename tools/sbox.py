import random

# 生成一个随机的 S 盒（包含 256 个独特的字节）
sbox = random.sample(range(256), 256)

# 输出 S 盒的 C 格式
print("uint8_t sbox[256] = {")
for i in range(0, 256, 16):  # 每行打印 16 项
    line = ", ".join(f"0x{sbox[j]:02X}" for j in range(i, i + 16))
    print(f"    {line},")
print("};")

# 生成逆 S 盒
inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

# 输出逆序 S 盒的 C 格式
print("\nuint8_t inv_sbox[256] = {")
for i in range(0, 256, 16):  # 每行打印 16 项
    line = ", ".join(f"0x{inv_sbox[j]:02X}" for j in range(i, i + 16))
    print(f"    {line},")
print("};")
