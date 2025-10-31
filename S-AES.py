import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget,
                             QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
                             QLineEdit, QPushButton, QTextEdit, QMessageBox,
                             QMenu, QAction)
from PyQt5.QtCore import Qt
import random


class SAES:
    # 核心加密算法类，无修改
    def __init__(self):
        self.S_BOX = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        self.INV_S_BOX = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]

        self.MIX_COLUMN_MATRIX = [[1, 4], [4, 1]]
        self.INV_MIX_COLUMN_MATRIX = [[9, 2], [2, 9]]
        self.RCON = [0x80, 0x30]

    def gf_mult(self, a, b):
        result = 0
        for _ in range(4):
            if b & 1:
                result ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            a &= 0xF
            if hi_bit_set:
                a ^= 0x3
            b >>= 1
        return result

    def key_expansion(self, key):
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF

        w2 = w0 ^ self.sub_nibbles(self.rot_nibble(w1)) ^ (self.RCON[0] >> 4)
        w3 = w2 ^ w1

        w4 = w2 ^ self.sub_nibbles(self.rot_nibble(w3)) ^ (self.RCON[1] >> 4)
        w5 = w4 ^ w3

        k0 = (w0 << 8) | w1
        k1 = (w2 << 8) | w3
        k2 = (w4 << 8) | w5

        return [k0, k1, k2]

    def sub_nibbles(self, byte):
        high_nibble = (byte >> 4) & 0xF
        low_nibble = byte & 0xF

        high_row = (high_nibble >> 2) & 0x3
        high_col = high_nibble & 0x3
        sub_high = self.S_BOX[high_row][high_col]

        low_row = (low_nibble >> 2) & 0x3
        low_col = low_nibble & 0x3
        sub_low = self.S_BOX[low_row][low_col]

        return (sub_high << 4) | sub_low

    def inv_sub_nibbles(self, byte):
        high_nibble = (byte >> 4) & 0xF
        low_nibble = byte & 0xF

        high_row = (high_nibble >> 2) & 0x3
        high_col = high_nibble & 0x3
        sub_high = self.INV_S_BOX[high_row][high_col]

        low_row = (low_nibble >> 2) & 0x3
        low_col = low_nibble & 0x3
        sub_low = self.INV_S_BOX[low_row][low_col]

        return (sub_high << 4) | sub_low

    def rot_nibble(self, byte):
        return ((byte & 0xF) << 4) | ((byte >> 4) & 0xF)

    def sub_bytes(self, state):
        result = 0
        for i in range(4):
            nibble = (state >> (4 * i)) & 0xF
            row = (nibble >> 2) & 0x3
            col = nibble & 0x3
            sub_nibble = self.S_BOX[row][col]
            result |= (sub_nibble << (4 * i))
        return result

    def inv_sub_bytes(self, state):
        result = 0
        for i in range(4):
            nibble = (state >> (4 * i)) & 0xF
            row = (nibble >> 2) & 0x3
            col = nibble & 0x3
            sub_nibble = self.INV_S_BOX[row][col]
            result |= (sub_nibble << (4 * i))
        return result

    def shift_rows(self, state):
        n0 = (state >> 12) & 0xF
        n1 = (state >> 8) & 0xF
        n2 = (state >> 4) & 0xF
        n3 = state & 0xF
        return (n0 << 12) | (n1 << 8) | (n3 << 4) | n2

    def mix_columns(self, state):
        s00 = (state >> 12) & 0xF
        s10 = (state >> 8) & 0xF
        s01 = (state >> 4) & 0xF
        s11 = state & 0xF

        t00 = self.gf_mult(self.MIX_COLUMN_MATRIX[0][0], s00) ^ self.gf_mult(self.MIX_COLUMN_MATRIX[0][1], s10)
        t10 = self.gf_mult(self.MIX_COLUMN_MATRIX[1][0], s00) ^ self.gf_mult(self.MIX_COLUMN_MATRIX[1][1], s10)
        t01 = self.gf_mult(self.MIX_COLUMN_MATRIX[0][0], s01) ^ self.gf_mult(self.MIX_COLUMN_MATRIX[0][1], s11)
        t11 = self.gf_mult(self.MIX_COLUMN_MATRIX[1][0], s01) ^ self.gf_mult(self.MIX_COLUMN_MATRIX[1][1], s11)

        return (t00 << 12) | (t10 << 8) | (t01 << 4) | t11

    def inv_mix_columns(self, state):
        s00 = (state >> 12) & 0xF
        s10 = (state >> 8) & 0xF
        s01 = (state >> 4) & 0xF
        s11 = state & 0xF

        t00 = self.gf_mult(self.INV_MIX_COLUMN_MATRIX[0][0], s00) ^ self.gf_mult(self.INV_MIX_COLUMN_MATRIX[0][1], s10)
        t10 = self.gf_mult(self.INV_MIX_COLUMN_MATRIX[1][0], s00) ^ self.gf_mult(self.INV_MIX_COLUMN_MATRIX[1][1], s10)
        t01 = self.gf_mult(self.INV_MIX_COLUMN_MATRIX[0][0], s01) ^ self.gf_mult(self.INV_MIX_COLUMN_MATRIX[0][1], s11)
        t11 = self.gf_mult(self.INV_MIX_COLUMN_MATRIX[1][0], s01) ^ self.gf_mult(self.INV_MIX_COLUMN_MATRIX[1][1], s11)

        return (t00 << 12) | (t10 << 8) | (t01 << 4) | t11

    def encrypt(self, plaintext, key):
        round_keys = self.key_expansion(key)
        state = plaintext ^ round_keys[0]

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.mix_columns(state)
        state = state ^ round_keys[1]

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = state ^ round_keys[2]

        return state

    def decrypt(self, ciphertext, key):
        round_keys = self.key_expansion(key)
        state = ciphertext ^ round_keys[2]
        state = self.shift_rows(state)
        state = self.inv_sub_bytes(state)

        state = state ^ round_keys[1]
        state = self.inv_mix_columns(state)
        state = self.shift_rows(state)
        state = self.inv_sub_bytes(state)

        state = state ^ round_keys[0]
        return state

    def ascii_to_blocks(self, text):
        blocks = []
        for i in range(0, len(text), 2):
            block = 0
            if i < len(text):
                block |= (ord(text[i]) << 8)
            if i + 1 < len(text):
                block |= ord(text[i + 1])
            blocks.append(block)
        return blocks

    def blocks_to_ascii(self, blocks):
        text = ""
        for block in blocks:
            char1 = (block >> 8) & 0xFF
            char2 = block & 0xFF
            if char1 != 0:
                text += chr(char1)
            if char2 != 0:
                text += chr(char2)
        return text

    def double_encrypt(self, plaintext, key):
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        return self.encrypt(self.encrypt(plaintext, key1), key2)

    def double_decrypt(self, ciphertext, key):
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        return self.decrypt(self.decrypt(ciphertext, key2), key1)

    def triple_encrypt_32bit(self, plaintext, key):
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        return self.encrypt(self.decrypt(self.encrypt(plaintext, key1), key2), key1)

    def triple_decrypt_32bit(self, ciphertext, key):
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF
        return self.decrypt(self.encrypt(self.decrypt(ciphertext, key1), key2), key1)

    def meet_in_middle_attack(self, plaintext, ciphertext):
        table = {}
        for k1 in range(0x1000):
            intermediate = self.encrypt(plaintext, k1)
            table[intermediate] = k1

        for k2 in range(0x1000):
            intermediate = self.decrypt(ciphertext, k2)
            if intermediate in table:
                k1 = table[intermediate]
                return (k1 << 16) | k2

        return None

    def cbc_encrypt(self, plaintext_blocks, key, iv):
        ciphertext_blocks = []
        prev_block = iv
        for block in plaintext_blocks:
            block ^= prev_block
            encrypted_block = self.encrypt(block, key)
            ciphertext_blocks.append(encrypted_block)
            prev_block = encrypted_block
        return ciphertext_blocks

    def cbc_decrypt(self, ciphertext_blocks, key, iv):
        plaintext_blocks = []
        prev_block = iv
        for block in ciphertext_blocks:
            decrypted_block = self.decrypt(block, key)
            decrypted_block ^= prev_block
            plaintext_blocks.append(decrypted_block)
            prev_block = block
        return plaintext_blocks


class SAESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-AES加密系统")
        self.resize(850, 750)

        # 左上角信息菜单栏
        self.create_info_menu()

        # 初始化加密核心类
        self.saes = SAES()

        # 主容器和选项卡
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        # 创建各个功能选项卡（已新增密文输入框）
        self.create_basic_tab()
        self.create_string_tab()
        self.create_multiple_tab()
        self.create_cbc_tab()

    def create_info_menu(self):
        menubar = self.menuBar()
        info_menu = menubar.addMenu("信息")
        about_action = QAction("关于", self)
        about_action.triggered.connect(self.show_about_dialog)
        info_menu.addAction(about_action)

    def show_about_dialog(self):
        about_text = (
            "S-AES加密系统\n"
            "版本号：v1.0.0\n\n"
            "核心功能：\n"
            "• 基础S-AES加密/解密（16位密钥）\n"
            "• ASCII字符串加密/解密\n"
            "• 双重加密与中间相遇攻击\n"
            "• 三重加密（32位密钥）\n"
            "• CBC工作模式与篡改测试\n\n"
            "开发框架：PyQt5\n"
            "开发人员：管俊杰 刘星远 许卓远"
        )
        QMessageBox.about(self, "关于S-AES加密系统", about_text)

    # ------------------------------
    # 1. 基本加密：新增密文输入框
    # ------------------------------
    def create_basic_tab(self):
        tab = QWidget()
        self.tab_widget.addTab(tab, "基本加密")
        layout = QVBoxLayout(tab)

        # 输入区域：新增“密文输入框”，与明文、密钥并列
        input_layout = QGridLayout()
        # 明文输入（加密用）
        plaintext_label = QLabel("明文 (16位十六进制):")
        self.basic_plaintext = QLineEdit("1234")
        input_layout.addWidget(plaintext_label, 0, 0, 1, 1)
        input_layout.addWidget(self.basic_plaintext, 0, 1, 1, 1)
        # 密文输入（解密用）- 新增
        ciphertext_label = QLabel("密文 (16位十六进制):")
        self.basic_ciphertext = QLineEdit("C98B")  # 默认填充示例密文
        input_layout.addWidget(ciphertext_label, 1, 0, 1, 1)
        input_layout.addWidget(self.basic_ciphertext, 1, 1, 1, 1)
        # 密钥输入（通用）
        key_label = QLabel("密钥 (16位十六进制):")
        self.basic_key = QLineEdit("5678")
        input_layout.addWidget(key_label, 2, 0, 1, 1)
        input_layout.addWidget(self.basic_key, 2, 1, 1, 1)
        layout.addLayout(input_layout)

        # 按钮区域（不变）
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("加密")
        decrypt_btn = QPushButton("解密")
        encrypt_btn.clicked.connect(self.basic_encrypt)
        decrypt_btn.clicked.connect(self.basic_decrypt)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        layout.addLayout(btn_layout)

        # 结果显示（不变）
        result_label = QLabel("结果:")
        self.basic_result = QTextEdit()
        self.basic_result.setReadOnly(True)
        layout.addWidget(result_label)
        layout.addWidget(self.basic_result)

    # ------------------------------
    # 2. 字符串加密：新增密文输入框
    # ------------------------------
    def create_string_tab(self):
        tab = QWidget()
        self.tab_widget.addTab(tab, "字符串加密")
        layout = QVBoxLayout(tab)

        # 输入区域：新增“密文输入框”（字符串格式）
        input_layout = QGridLayout()
        # 明文输入（加密用）
        plaintext_label = QLabel("明文 (ASCII字符串):")
        self.str_plaintext = QLineEdit("Hello")
        input_layout.addWidget(plaintext_label, 0, 0, 1, 1)
        input_layout.addWidget(self.str_plaintext, 0, 1, 1, 2)
        # 密文输入（解密用）- 新增
        ciphertext_label = QLabel("密文 (ASCII字符串):")
        self.str_ciphertext = QLineEdit("\x1c\x9f\x8e\x1d\x00")  # 示例密文（Hello加密结果）
        input_layout.addWidget(ciphertext_label, 1, 0, 1, 1)
        input_layout.addWidget(self.str_ciphertext, 1, 1, 1, 2)
        # 密钥输入（通用）
        key_label = QLabel("密钥 (16位十六进制):")
        self.str_key = QLineEdit("1234")
        input_layout.addWidget(key_label, 2, 0, 1, 1)
        input_layout.addWidget(self.str_key, 2, 1, 1, 2)
        layout.addLayout(input_layout)

        # 按钮区域（不变）
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("字符串加密")
        decrypt_btn = QPushButton("字符串解密")
        encrypt_btn.clicked.connect(self.str_encrypt)
        decrypt_btn.clicked.connect(self.str_decrypt)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        layout.addLayout(btn_layout)

        # 结果显示（不变）
        self.str_result = QTextEdit()
        self.str_result.setReadOnly(True)
        layout.addWidget(self.str_result)

    # ------------------------------
    # 3. 多重加密：双重/三重加密均新增密文输入框
    # ------------------------------
    def create_multiple_tab(self):
        main_tab = QWidget()
        self.tab_widget.addTab(main_tab, "多重加密")
        main_layout = QVBoxLayout(main_tab)

        sub_tab = QTabWidget()
        main_layout.addWidget(sub_tab)

        # 3.1 双重加密：新增密文输入框
        double_tab = QWidget()
        sub_tab.addTab(double_tab, "双重加密")
        double_layout = QVBoxLayout(double_tab)

        input_layout = QGridLayout()
        # 明文输入（加密用）
        plaintext_label = QLabel("明文 (16位十六进制):")
        self.double_plaintext = QLineEdit("1234")
        input_layout.addWidget(plaintext_label, 0, 0)
        input_layout.addWidget(self.double_plaintext, 0, 1)
        # 密文输入（解密用）- 新增
        ciphertext_label = QLabel("密文 (16位十六进制):")
        self.double_ciphertext = QLineEdit("A7B2")  # 示例密文
        input_layout.addWidget(ciphertext_label, 1, 0)
        input_layout.addWidget(self.double_ciphertext, 1, 1)
        # 密钥输入（通用）
        key_label = QLabel("密钥 (32位十六进制):")
        self.double_key = QLineEdit("12345678")
        input_layout.addWidget(key_label, 2, 0)
        input_layout.addWidget(self.double_key, 2, 1)
        double_layout.addLayout(input_layout)

        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("双重加密")
        decrypt_btn = QPushButton("双重解密")
        encrypt_btn.clicked.connect(self.double_encrypt)
        decrypt_btn.clicked.connect(self.double_decrypt)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        double_layout.addLayout(btn_layout)

        self.double_result = QTextEdit()
        self.double_result.setReadOnly(True)
        double_layout.addWidget(self.double_result)

        # 3.2 中间相遇攻击（无需密文输入框，已有已知密文框，不变）
        meet_tab = QWidget()
        sub_tab.addTab(meet_tab, "中间相遇攻击")
        meet_layout = QVBoxLayout(meet_tab)

        input_layout = QGridLayout()
        plaintext_label = QLabel("已知明文 (16位):")
        self.meet_plaintext = QLineEdit("1234")
        input_layout.addWidget(plaintext_label, 0, 0)
        input_layout.addWidget(self.meet_plaintext, 0, 1)

        ciphertext_label = QLabel("已知密文 (16位):")
        self.meet_ciphertext = QLineEdit("C98B")
        input_layout.addWidget(ciphertext_label, 1, 0)
        input_layout.addWidget(self.meet_ciphertext, 1, 1)
        meet_layout.addLayout(input_layout)

        attack_btn = QPushButton("执行中间相遇攻击")
        attack_btn.clicked.connect(self.meet_attack)
        meet_layout.addWidget(attack_btn)

        self.meet_result = QTextEdit()
        self.meet_result.setReadOnly(True)
        meet_layout.addWidget(self.meet_result)

        # 3.3 三重加密：新增密文输入框
        triple_tab = QWidget()
        sub_tab.addTab(triple_tab, "三重加密")
        triple_layout = QVBoxLayout(triple_tab)

        input_layout = QGridLayout()
        # 明文输入（加密用）
        plaintext_label = QLabel("明文 (16位十六进制):")
        self.triple_plaintext = QLineEdit("1234")
        input_layout.addWidget(plaintext_label, 0, 0)
        input_layout.addWidget(self.triple_plaintext, 0, 1)
        # 密文输入（解密用）- 新增
        ciphertext_label = QLabel("密文 (16位十六进制):")
        self.triple_ciphertext = QLineEdit("D8E7")  # 示例密文
        input_layout.addWidget(ciphertext_label, 1, 0)
        input_layout.addWidget(self.triple_ciphertext, 1, 1)
        # 密钥输入（通用）
        key_label = QLabel("密钥 (32位十六进制):")
        self.triple_key = QLineEdit("12345678")
        input_layout.addWidget(key_label, 2, 0)
        input_layout.addWidget(self.triple_key, 2, 1)
        triple_layout.addLayout(input_layout)

        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("三重加密")
        decrypt_btn = QPushButton("三重解密")
        encrypt_btn.clicked.connect(self.triple_encrypt)
        decrypt_btn.clicked.connect(self.triple_decrypt)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        triple_layout.addLayout(btn_layout)

        self.triple_result = QTextEdit()
        self.triple_result.setReadOnly(True)
        triple_layout.addWidget(self.triple_result)

    # ------------------------------
    # 4. CBC模式：新增密文输入框
    # ------------------------------
    def create_cbc_tab(self):
        tab = QWidget()
        self.tab_widget.addTab(tab, "CBC模式")
        layout = QVBoxLayout(tab)

        # 输入区域：新增“密文输入框”（字符串格式）
        input_layout = QGridLayout()
        # 明文输入（加密用）
        plaintext_label = QLabel("明文 (ASCII字符串):")
        self.cbc_plaintext = QLineEdit("Hello World!")
        input_layout.addWidget(plaintext_label, 0, 0, 1, 1)
        input_layout.addWidget(self.cbc_plaintext, 0, 1, 1, 2)
        # 密文输入（解密用）- 新增
        ciphertext_label = QLabel("密文 (ASCII字符串):")
        self.cbc_ciphertext = QLineEdit("\x9a\x1e\x8f\x0c\x7d\x2b\x3f\x1a\x0e\x4c\x9b\x00")  # 示例密文
        input_layout.addWidget(ciphertext_label, 1, 0, 1, 1)
        input_layout.addWidget(self.cbc_ciphertext, 1, 1, 1, 2)
        # 密钥输入（通用）
        key_label = QLabel("密钥 (16位十六进制):")
        self.cbc_key = QLineEdit("1234")
        input_layout.addWidget(key_label, 2, 0, 1, 1)
        input_layout.addWidget(self.cbc_key, 2, 1, 1, 2)
        # IV输入（通用）
        iv_label = QLabel("初始向量 (16位十六进制):")
        self.cbc_iv = QLineEdit("5678")
        input_layout.addWidget(iv_label, 3, 0, 1, 1)
        input_layout.addWidget(self.cbc_iv, 3, 1, 1, 2)
        layout.addLayout(input_layout)

        # 按钮区域（不变）
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("CBC加密")
        decrypt_btn = QPushButton("CBC解密")
        tamper_btn = QPushButton("篡改测试")
        encrypt_btn.clicked.connect(self.cbc_encrypt)
        decrypt_btn.clicked.connect(self.cbc_decrypt)
        tamper_btn.clicked.connect(self.cbc_tamper)
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(tamper_btn)
        layout.addLayout(btn_layout)

        # 结果显示（不变）
        self.cbc_result = QTextEdit()
        self.cbc_result.setReadOnly(True)
        layout.addWidget(self.cbc_result)

    # ------------------------------
    # 功能逻辑：修改解密函数，读取新增的密文输入框
    # ------------------------------
    def basic_encrypt(self):
        try:
            plaintext = int(self.basic_plaintext.text(), 16)
            key = int(self.basic_key.text(), 16)
            ciphertext = self.saes.encrypt(plaintext, key)

            self.basic_result.clear()
            self.basic_result.insertPlainText(
                f"明文: 0x{plaintext:04X}\n"
                f"密钥: 0x{key:04X}\n"
                f"密文: 0x{ciphertext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def basic_decrypt(self):
        try:
            # 解密时读取“密文输入框”，而非原明文输入框
            ciphertext = int(self.basic_ciphertext.text(), 16)
            key = int(self.basic_key.text(), 16)
            plaintext = self.saes.decrypt(ciphertext, key)

            self.basic_result.clear()
            self.basic_result.insertPlainText(
                f"密文: 0x{ciphertext:04X}\n"
                f"密钥: 0x{key:04X}\n"
                f"明文: 0x{plaintext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def str_encrypt(self):
        try:
            plaintext = self.str_plaintext.text()
            key = int(self.str_key.text(), 16)

            blocks = self.saes.ascii_to_blocks(plaintext)
            encrypted_blocks = [self.saes.encrypt(b, key) for b in blocks]
            encrypted_text = self.saes.blocks_to_ascii(encrypted_blocks)

            self.str_result.clear()
            self.str_result.insertPlainText(
                f"原始文本: {plaintext}\n"
                f"文本块: {[hex(b) for b in blocks]}\n"
                f"加密块: {[hex(b) for b in encrypted_blocks]}\n"
                f"加密文本: {encrypted_text}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制密钥！")

    def str_decrypt(self):
        try:
            # 解密时读取“密文输入框”，而非原明文输入框
            ciphertext = self.str_ciphertext.text()
            key = int(self.str_key.text(), 16)

            blocks = self.saes.ascii_to_blocks(ciphertext)
            decrypted_blocks = [self.saes.decrypt(b, key) for b in blocks]
            decrypted_text = self.saes.blocks_to_ascii(decrypted_blocks)

            self.str_result.clear()
            self.str_result.insertPlainText(
                f"加密文本: {ciphertext}\n"
                f"加密块: {[hex(b) for b in blocks]}\n"
                f"解密块: {[hex(b) for b in decrypted_blocks]}\n"
                f"解密文本: {decrypted_text}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制密钥！")

    def double_encrypt(self):
        try:
            plaintext = int(self.double_plaintext.text(), 16)
            key = int(self.double_key.text(), 16)
            ciphertext = self.saes.double_encrypt(plaintext, key)

            self.double_result.clear()
            self.double_result.insertPlainText(
                f"明文: 0x{plaintext:04X}\n"
                f"密钥: 0x{key:08X}\n"
                f"双重加密结果: 0x{ciphertext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def double_decrypt(self):
        try:
            # 解密时读取“密文输入框”，而非原明文输入框
            ciphertext = int(self.double_ciphertext.text(), 16)
            key = int(self.double_key.text(), 16)
            plaintext = self.saes.double_decrypt(ciphertext, key)

            self.double_result.clear()
            self.double_result.insertPlainText(
                f"密文: 0x{ciphertext:04X}\n"
                f"密钥: 0x{key:08X}\n"
                f"双重解密结果: 0x{plaintext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def meet_attack(self):
        try:
            plaintext = int(self.meet_plaintext.text(), 16)
            ciphertext = int(self.meet_ciphertext.text(), 16)

            self.meet_result.clear()
            self.meet_result.insertPlainText("正在执行中间相遇攻击...\n")
            QApplication.processEvents()

            found_key = self.saes.meet_in_middle_attack(plaintext, ciphertext)
            if found_key:
                key1 = (found_key >> 16) & 0xFFFF
                key2 = found_key & 0xFFFF
                self.meet_result.insertPlainText(
                    f"攻击成功！\n"
                    f"找到的32位密钥: 0x{found_key:08X}\n"
                    f"拆分密钥 K1: 0x{key1:04X}, K2: 0x{key2:04X}\n"
                )
            else:
                self.meet_result.insertPlainText("攻击失败！未找到匹配的密钥。\n")
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def triple_encrypt(self):
        try:
            plaintext = int(self.triple_plaintext.text(), 16)
            key = int(self.triple_key.text(), 16)
            ciphertext = self.saes.triple_encrypt_32bit(plaintext, key)

            self.triple_result.clear()
            self.triple_result.insertPlainText(
                f"明文: 0x{plaintext:04X}\n"
                f"密钥: 0x{key:08X}\n"
                f"三重加密结果: 0x{ciphertext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def triple_decrypt(self):
        try:
            # 解密时读取“密文输入框”，而非原明文输入框
            ciphertext = int(self.triple_ciphertext.text(), 16)
            key = int(self.triple_key.text(), 16)
            plaintext = self.saes.triple_decrypt_32bit(ciphertext, key)

            self.triple_result.clear()
            self.triple_result.insertPlainText(
                f"密文: 0x{ciphertext:04X}\n"
                f"密钥: 0x{key:08X}\n"
                f"三重解密结果: 0x{plaintext:04X}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的16进制数！")

    def cbc_encrypt(self):
        try:
            plaintext = self.cbc_plaintext.text()
            key = int(self.cbc_key.text(), 16)
            iv = int(self.cbc_iv.text(), 16)

            blocks = self.saes.ascii_to_blocks(plaintext)
            encrypted_blocks = self.saes.cbc_encrypt(blocks, key, iv)
            encrypted_text = self.saes.blocks_to_ascii(encrypted_blocks)

            self.cbc_result.clear()
            self.cbc_result.insertPlainText(
                f"原始文本: {plaintext}\n"
                f"文本块: {[hex(b) for b in blocks]}\n"
                f"加密块: {[hex(b) for b in encrypted_blocks]}\n"
                f"CBC加密文本: {encrypted_text}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的密钥和初始向量！")

    def cbc_decrypt(self):
        try:
            # 解密时读取“密文输入框”，而非原明文输入框
            ciphertext = self.cbc_ciphertext.text()
            key = int(self.cbc_key.text(), 16)
            iv = int(self.cbc_iv.text(), 16)

            blocks = self.saes.ascii_to_blocks(ciphertext)
            decrypted_blocks = self.saes.cbc_decrypt(blocks, key, iv)
            decrypted_text = self.saes.blocks_to_ascii(decrypted_blocks)

            self.cbc_result.clear()
            self.cbc_result.insertPlainText(
                f"加密文本: {ciphertext}\n"
                f"加密块: {[hex(b) for b in blocks]}\n"
                f"解密块: {[hex(b) for b in decrypted_blocks]}\n"
                f"CBC解密文本: {decrypted_text}\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的密钥和初始向量！")

    def cbc_tamper(self):
        try:
            plaintext = self.cbc_plaintext.text() or "Hello World!"
            key = int(self.cbc_key.text() or "1234", 16)
            iv = int(self.cbc_iv.text() or "5678", 16)

            blocks = self.saes.ascii_to_blocks(plaintext)
            encrypted_blocks = self.saes.cbc_encrypt(blocks, key, iv)
            tampered_blocks = encrypted_blocks.copy()
            if len(tampered_blocks) > 1:
                tampered_blocks[1] ^= 0x0F0F
            decrypted_blocks = self.saes.cbc_decrypt(tampered_blocks, key, iv)
            decrypted_text = self.saes.blocks_to_ascii(decrypted_blocks)

            self.cbc_result.clear()
            self.cbc_result.insertPlainText(
                "CBC模式篡改测试结果\n"
                "===================================================\n" 
                f"原始文本: {plaintext}\n"
                f"正常加密块: {[hex(b) for b in encrypted_blocks]}\n"
                f"篡改后加密块: {[hex(b) for b in tampered_blocks]}\n"
                f"篡改后解密文本: {decrypted_text}\n"
                "===================================================\n" 
                "结论：CBC模式下，单个密文块篡改会影响当前及下一个解密块！\n"
            )
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的密钥和初始向量！")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SAESGUI()
    window.show()
    sys.exit(app.exec_())
