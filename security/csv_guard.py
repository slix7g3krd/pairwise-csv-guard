"""CSV 导出公式注入（CSV/Excel Formula Injection）防护核心。

防护清单（与 README 一一对应）：

1. 危险前缀转义：``= + - @`` 开头的单元格前置单引号，阻止 Excel 按公式执行；
2. 制表符与回车清理：剥离用于绕过首字符检测的前置 ``\\t`` / ``\\r`` 等字符；
3. 引号内公式检测：检测前剥离开头的双引号，``"=1"`` 同样判定为公式；
4. BOM 与零宽字符归一：剥离 BOM、ZWSP/ZWNJ/ZWJ 等混淆字符后再判定；
5. 分隔符转义：含逗号/双引号/换行的值按 RFC 4180 加引号包裹，防止伪造列；
6. 表头白名单：``sanitize_header`` 支持白名单校验，非法表头拒绝；
7. 编码固定：统一以 UTF-8（带 BOM，兼容 Excel）导出；
8. 换行处理：单元格内换行/制表符折叠为空格，防止一行被拆成多行；
9. 文件名净化：``safe_filename`` 去除 CRLF、路径分隔符与危险前缀，防响应头注入；
10. 导出前统一编码：``render_csv`` 先净化再编码，调用方无法跳过防护。
"""

import re
import unicodedata
from urllib.parse import quote

# Excel / 电子表格软件会当作公式触发的首字符
FORMULA_PREFIXES = ('=', '+', '-', '@')
# 用于中和公式的前导符：Excel 会把以单引号开头的单元格按纯文本处理
NEUTRALIZER = "'"

# BOM 与常见零宽 / 不可见混淆字符（显式转义，避免源码里混入不可见字面量）
INVISIBLE_CHARS = (
    '\ufeff',  # BOM / ZERO WIDTH NO-BREAK SPACE
    '\u200b',  # ZERO WIDTH SPACE
    '\u200c',  # ZERO WIDTH NON-JOINER
    '\u200d',  # ZERO WIDTH JOINER
    '\u200e',  # LEFT-TO-RIGHT MARK
    '\u200f',  # RIGHT-TO-LEFT MARK
    '\u2028',  # LINE SEPARATOR
    '\u2029',  # PARAGRAPH SEPARATOR
    '\u00ad',  # SOFT HYPHEN
    '\u2060',  # WORD JOINER
)
_INVISIBLE_TABLE = {ord(ch): None for ch in INVISIBLE_CHARS}

# 单元格内需要折叠成空格的分隔类控制字符（换行、制表符等）
_BREAK_RUN_RE = re.compile(r'[\t\n\r\v\f]+')


def _to_text(value):
    """把任意输入归一为字符串（None 视为空串）。"""
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return str(value)


def _strip_leading_obfuscation(text):
    """剥离开头用于绕过首字符检测的混淆字符。

    覆盖：ASCII/Unicode 空白（含制表符、回车）、所有控制字符（Cc）、
    格式字符（Cf，含 BOM、零宽字符、双向标记）、分隔符（Z*）。
    """
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if ch in INVISIBLE_CHARS:
            index += 1
            continue
        category = unicodedata.category(ch)
        if ch.isspace() or category in ('Cc', 'Cf', 'Zl', 'Zp', 'Zs'):
            index += 1
            continue
        break
    return text[index:]


def is_formula(value):
    """判定一个单元格值是否会被电子表格软件当作公式执行。

    检测前先做归一化：剥离前置空白/控制字符/零宽字符/BOM，再剥离开头的
    双引号，最后检查危险首字符。前置单引号是 Excel 的文本标记，视为安全。
    """
    text = _to_text(value)
    # 去掉正文中的零宽字符，避免嵌在引号/前缀之间的混淆
    text = text.translate(_INVISIBLE_TABLE)
    text = _strip_leading_obfuscation(text)
    # 双引号包裹后公式仍然生效：剥离开头的双引号再判定
    while text.startswith('"'):
        text = text[1:]
        text = _strip_leading_obfuscation(text)
    if not text:
        return False
    # 前导单引号已把单元格标记为文本
    if text.startswith(NEUTRALIZER):
        return False
    return text[0] in FORMULA_PREFIXES


def _quote_rfc4180(text):
    """按 RFC 4180 包裹含分隔符、双引号或换行的字段。"""
    if any(ch in text for ch in (',', '"', '\n', '\r')):
        return '"' + text.replace('"', '""') + '"'
    return text


def escape_cell(value):
    """转义单个单元格值，返回可安全写入 CSV 的文本。

    - 公式（含各种混淆前缀）→ 前置单引号中和，如 ``=cmd`` → ``'=cmd``；
    - 含双引号的公式（如 ``"=1"``，引号包裹后公式仍会生效）→
      直接用单引号整体包裹原文：``'"=1"'``，包裹引号同时承担中和作用；
    - 普通字段含逗号/双引号/换行 → RFC 4180 双引号包裹，防分隔符注入；
    - 普通文本 → 原样返回。
    """
    text = _to_text(value)
    if is_formula(text):
        if '"' in text:
            return NEUTRALIZER + text + NEUTRALIZER
        return NEUTRALIZER + text
    return _quote_rfc4180(text)


def _clean_cell_text(text):
    """清理单元格正文：去零宽字符，换行/制表符折叠为空格。

    防止单元格内换行把一条记录拆成多行、制表符/零宽字符做检测绕过。
    """
    text = text.translate(_INVISIBLE_TABLE)
    text = _BREAK_RUN_RE.sub(' ', text)
    return text.strip()


def sanitize_row(row):
    """净化一整行：先清理每个单元格，再做公式/分隔符转义。"""
    if not row:
        return []
    return [escape_cell(_clean_cell_text(_to_text(cell))) for cell in row]


def sanitize_header(header, allowed=None):
    """净化表头。

    表头同样可能来自用户输入并携带公式。提供 ``allowed`` 白名单时，
    不在白名单内的表头抛 ``ValueError``；否则按单元格规则净化。
    """
    text = _clean_cell_text(_to_text(header))
    if allowed is not None:
        if text not in allowed:
            raise ValueError('header not in whitelist: %r' % (header,))
        return text
    return escape_cell(text)


# 文件名中一律剔除的控制字符（含 CR/LF/TAB，防 HTTP 响应头拆分与 CRLF 注入）
_FILENAME_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')
# 路径分隔符与文件名非法字符（防目录穿越、写任意路径）
_FILENAME_BAD_CHARS_RE = re.compile(r'[\\/:*?"<>|~]')
# 文件名开头的危险/无意义字符（公式前缀、点、空白）
_FILENAME_LEADING_RE = re.compile(r'^[=+\-\s.@]+')
_SPACE_RUN_RE = re.compile(r'\s+')


def safe_filename(filename, default='export.csv'):
    """净化下载文件名，防 Content-Disposition 头注入与路径穿越。

    - 删除 BOM/零宽字符与全部控制字符（含 ``\\r``、``\\n``）；
    - 路径分隔符与通配符替换为下划线，拒绝 ``..`` 穿越；
    - 去掉开头的公式前缀字符，避免文件名被下游表格软件解析；
    - 空白折叠；结果为空或仅含点号时回退到默认名。
    """
    text = _to_text(filename).translate(_INVISIBLE_TABLE)
    text = _FILENAME_CONTROL_RE.sub('', text)
    text = _FILENAME_BAD_CHARS_RE.sub('_', text)
    text = _FILENAME_LEADING_RE.sub('', text)
    text = _SPACE_RUN_RE.sub(' ', text).strip()
    if not text or set(text) == {'.'}:
        return default
    return text


def render_csv(rows, headers=None):
    """导出前的统一安全出口：净化表头与每一行，再按固定编码输出字节。

    编码固定为 UTF-8-SIG（带 BOM），Excel 打开不会乱码、也不会因编码
    声明错误把内容按公式/错误字符集解析。字段已由 ``escape_cell`` 按
    RFC 4180 转义，这里直接拼接，避免 csv 模块二次包裹。返回 ``bytes``。
    """
    lines = []
    if headers is not None:
        lines.append(','.join(sanitize_header(h) for h in headers))
    for row in rows:
        lines.append(','.join(sanitize_row(row)))
    payload = '\r\n'.join(lines)
    if payload:
        payload += '\r\n'
    # utf-8-sig 写入 BOM，固定编码，调用方不得自行指定其他编码
    return payload.encode('utf-8-sig')


def build_download_headers(filename, media_type='text/csv; charset=utf-8'):
    """构造安全的下载响应头：文件名经净化，编码显式声明。

    同时给出 ASCII 回退名与 RFC 5987 的 ``filename*``（支持非 ASCII），
    净化过程移除 CRLF，杜绝响应头拆分注入。
    """
    safe_name = safe_filename(filename)
    ascii_name = safe_name.encode('ascii', 'ignore').decode('ascii') or 'export.csv'
    ascii_name = ascii_name.replace('\\', '_').replace('"', "'")
    return {
        'Content-Type': media_type,
        'Content-Disposition': (
            "attachment; filename=\"%s\"; filename*=UTF-8''%s"
            % (ascii_name, quote(safe_name))
        ),
    }
