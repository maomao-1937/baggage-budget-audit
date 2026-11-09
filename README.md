# Baggage Budget Audit

[![tests](https://github.com/maomao-1937/baggage-budget-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/baggage-budget-audit/actions/workflows/tests.yml)

Check whether a saved W3C Baggage header value follows the published grammar and fits both minimum propagation thresholds. The JSON report gives byte and member counts and duplicate positions while keeping keys, values, properties and file paths private.

## Quick start

Use Python 3.11 or later on Windows or Linux. From the repository root, run the bundled examples.

```sh
python baggage_budget_audit.py examples/within-budget.raw
python baggage_budget_audit.py examples/member-budget.raw
python baggage_budget_audit.py examples/byte-budget.raw
python baggage_budget_audit.py examples/invalid-newline.raw
```

The first example exits 0 and reports the third member as a duplicate. The next two exit 1 because they exceed one threshold each. The last exits 2 because the file ends in a line feed.

```json
{"status":"ok","bytes":62,"members":3,"byte_budget_exceeded":false,"member_budget_exceeded":false,"duplicate_member_ordinals":[3]}
```

## Input and report

- `HEADER` is a regular local file containing exactly one raw header value up to 256 KiB. Save only the value, omitting the `baggage:` prefix and any line break. The CLI counts every byte in the saved value, including separator commas and permitted whitespace. Use a trusted local directory because path spelling checks cannot determine where filesystem links or mounts lead.
- The grammar accepts 1–180 comma-separated members. A member has a nonempty ASCII token key, an equals sign, a possibly empty value, and optional semicolon-delimited properties. Each property has a token key and may have a value. Space and tab are allowed around keys, values and separators. Values can contain equals signs and `%HH` escapes, including escapes for octets that would be invalid UTF-8 if decoded.
- `duplicate_member_ordinals` gives one-based positions of repeated member keys after their first occurrence. Key equality is case-sensitive and uses the raw token bytes. Properties do not participate, and duplicates do not independently change the exit code.
- The thresholds are 8192 bytes and 64 members, inclusive. They are the W3C minimum conditions for propagating the whole value. A platform may support higher limits. The CLI reports validity and budgets for the saved value only. [W3C Baggage §3.3](https://www.w3.org/TR/baggage/#header-content)

| Exit | Report |
| --- | --- |
| 0 | `ok` for valid grammar within both thresholds. Help also exits 0. |
| 1 | `over_budget` for valid grammar exceeding either threshold. |
| 2 | `invalid` for bad arguments, malformed input or a read failure. If stdout is unavailable, the command exits 2 quietly. |

The CLI operates on the saved bytes and keeps percent escapes encoded. It takes a single value and performs no HTTP capture parsing, combination, rewriting or live propagation.

## 中文

这个工具离线检查一份保存下来的 W3C Baggage 请求头值，判断语法是否有效，以及是否超过 8192 字节或 64 项的传播阈值。报告给出原始字节数、成员数、超限标记和重复项位置，省略键、值、属性和文件路径。

在 Windows 或 Linux 使用 Python 3.11 或更高版本，按上方命令运行仓库里的示例。四个示例的退出码依次为 0、1、1、2。第一个示例中第 3 项重复。第二、第三个示例分别超出成员数和字节数阈值。第四个示例带有结尾换行，语法无效。

输入是一个 256 KiB 以内的本地常规文件，只保存头值，去掉 `baggage:` 前缀和换行。支持 1–180 个语法有效的逗号分隔成员，按原样计入空格、制表符和分隔符的字节数。值可为空，也可包含等号或 `%HH` 转义。重复项按原始键的大小写敏感比较，从 1 开始编号。退出码 0 表示语法有效且两个阈值都未超出，1 表示语法有效但超限，2 表示调用、输入或输出失败。

See [research](RESEARCH.md) and [tests](TESTING.md). MIT licensed.
