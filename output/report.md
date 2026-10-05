# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-10-05 05:15:18 | 源：18/18 | 缓存命中：5

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 3,478,164 |
| Allow 白名单 | 62 |
| 综合去重率 | 15.3% |
| 聚合精简 | 39,423 |
| 冲突消解 | 7 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 51.1s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 4,106,997 | - |
| 去重后（精确 584,806 / 规范化 4,529 / 正则 0） | 3,517,662 | -589,335 |
| 聚合后（精确 39,421 / 通配符 2 / 升级 0） | 3,478,239 | -39,423 |
| 冲突消解后 | 3,478,226 | -7 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 3,478,090 |
| ip | 72 |
| regex | 63 |
| wildcard | 1 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,549,853 |
| other | 589,021 |
| ads | 278,989 |
| phishing | 59,760 |
| tracking | 373 |
| mining | 168 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,550,923 | 2,548,334 | 99.9% | 2,389,044 | 159,290 | 93.7% |
| HaGeZi's Gambling Blocklist | 580,044 | 580,020 | 100.0% | 573,405 | 6,615 | 98.9% |
| HaGeZi's Ultimate Blocklist | 236,129 | 234,909 | 99.5% | 75,293 | 159,616 | 32.1% |
| Phishing Army | 145,091 | 122,672 | 84.5% | 33,236 | 89,436 | 27.1% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,092 | 15,832 | 98.4% | 14,330 | 1,502 | 90.5% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 37,324 | 33,773 | 90.5% | 13,973 | 19,800 | 41.4% |
| CHN: AdRules DNS List | 197,482 | 193,660 | 98.1% | 11,779 | 181,881 | 6.1% |
| CHN: anti-AD | 100,094 | 99,387 | 99.3% | 7,848 | 91,539 | 7.9% |
| AdGuard DNS filter | 177,716 | 175,430 | 98.7% | 4,975 | 170,455 | 2.8% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 100.0% | 1,286 | 90 | 93.5% |
| Malicious URL Blocklist (URLHaus) | 3,128 | 2,506 | 80.1% | 976 | 1,530 | 38.9% |
| Stalkerware Indicators List | 928 | 509 | 54.8% | 448 | 61 | 88.0% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 100.0% | 16 | 0 | 100.0% |
| OISD Blocklist Small | 58,132 | 56,697 | 97.5% | 9 | 56,688 | 0.0% |
| Scam Blocklist by DurableNapkin | 931 | 928 | 99.7% | 4 | 924 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 381 | 373 | 97.9% | 1 | 372 | 0.3% |
| AWAvenue Ads Rule | 898 | 744 | 82.9% | 0 | 744 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **2,548,334** | 🟩 5,532 (0.2%) | 🟩 78,648 (2.9%) | 🟩 14,127 (0.5%) | 🟩 12,441 (0.5%) | 🟩 77,086 (3.0%) | 🟩 9,613 (0.4%) | 🟩 10,228 (0.4%) | 🟩 7,374 (0.3%) | 🟩 131 (0.0%) | 🟩 1,464 (0.1%) | 🟩 11 (0.0%) | 🟩 825 (0.0%) | 🟩 7 (0.0%) | 🟩 44 (0.0%) | · | 🟩 100 (0.0%) | · |
| **2** | 🟩 5,532 (0.2%) | **580,020** | 🟩 1,500 (0.2%) | 🟩 429 (0.1%) | 🟩 389 (0.1%) | 🟩 162 (0.0%) | 🟩 203 (0.0%) | 🟩 127 (0.0%) | 🟩 11 (0.0%) | 🟩 1 (0.0%) | 🟩 17 (0.0%) | · | 🟩 2 (0.0%) | · | · | · | · | · |
| **3** | 🟩 78,648 (2.9%) | 🟩 1,500 (0.2%) | **234,909** | 🟨 80,393 (23.1%) | 🟨 79,545 (24.0%) | 🟩 6,930 (2.0%) | 🟨 58,465 (21.2%) | 🟨 56,616 (24.1%) | 🟩 1,070 (0.4%) | 🟩 1,440 (0.6%) | 🟩 140 (0.1%) | 🟩 77 (0.0%) | 🟩 367 (0.2%) | 🟩 725 (0.3%) | 🟩 23 (0.0%) | 🟩 372 (0.2%) | 🟩 103 (0.0%) | · |
| **4** | 🟩 14,127 (0.5%) | 🟩 429 (0.1%) | 🟨 80,393 (23.1%) | **193,660** | 🟧 162,749 (78.9%) | 🟩 26 (0.0%) | 🟨 85,791 (41.4%) | 🟨 53,084 (26.9%) | 🟩 31 (0.0%) | 🟩 81 (0.0%) | 🟩 10 (0.0%) | 🟩 34 (0.0%) | 🟩 924 (0.5%) | 🟩 564 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 12,441 (0.5%) | 🟩 389 (0.1%) | 🟨 79,545 (24.0%) | 🟧 162,749 (78.9%) | **175,430** | 🟩 17 (0.0%) | 🟨 76,507 (38.6%) | 🟨 52,533 (29.3%) | 🟩 24 (0.0%) | 🟩 31 (0.0%) | 🟩 2 (0.0%) | 🟩 29 (0.0%) | 🟩 21 (0.0%) | 🟩 240 (0.1%) | 🟩 2 (0.0%) | 🟩 24 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 77,086 (3.0%) | 🟩 162 (0.0%) | 🟩 6,930 (2.0%) | 🟩 26 (0.0%) | 🟩 17 (0.0%) | **122,672** | 🟩 12 (0.0%) | 🟩 6 (0.0%) | 🟩 18,885 (13.7%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | · | 🟩 3 (0.0%) | · | · | · | 🟩 1 (0.0%) | · |
| **7** | 🟩 9,613 (0.4%) | 🟩 203 (0.0%) | 🟨 58,465 (21.2%) | 🟨 85,791 (41.4%) | 🟨 76,507 (38.6%) | 🟩 12 (0.0%) | **99,387** | 🟨 40,934 (35.5%) | 🟩 25 (0.0%) | 🟩 30 (0.0%) | 🟩 435 (0.4%) | 🟩 25 (0.0%) | 🟩 10 (0.0%) | 🟩 712 (0.7%) | 🟩 5 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 10,228 (0.4%) | 🟩 127 (0.0%) | 🟨 56,616 (24.1%) | 🟨 53,084 (26.9%) | 🟨 52,533 (29.3%) | 🟩 6 (0.0%) | 🟨 40,934 (35.5%) | **56,697** | 🟩 11 (0.0%) | 🟩 21 (0.0%) | 🟩 6 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 691 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 7,374 (0.3%) | 🟩 11 (0.0%) | 🟩 1,070 (0.4%) | 🟩 31 (0.0%) | 🟩 24 (0.0%) | 🟩 18,885 (13.7%) | 🟩 25 (0.0%) | 🟩 11 (0.0%) | **33,773** | 🟩 9 (0.0%) | 🟩 27 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 3 (0.0%) | · |
| **10** | 🟩 131 (0.0%) | 🟩 1 (0.0%) | 🟩 1,440 (0.6%) | 🟩 81 (0.0%) | 🟩 31 (0.0%) | 🟩 10 (0.0%) | 🟩 30 (0.0%) | 🟩 21 (0.0%) | 🟩 9 (0.0%) | **15,832** | 🟩 6 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,464 (0.1%) | 🟩 17 (0.0%) | 🟩 140 (0.1%) | 🟩 10 (0.0%) | 🟩 2 (0.0%) | 🟩 13 (0.0%) | 🟩 435 (0.4%) | 🟩 6 (0.0%) | 🟩 27 (0.1%) | 🟩 6 (0.0%) | **2,506** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 11 (0.0%) | · | 🟩 77 (0.0%) | 🟩 34 (0.0%) | 🟩 29 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,376** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 825 (0.0%) | 🟩 2 (0.0%) | 🟩 367 (0.2%) | 🟩 924 (0.5%) | 🟩 21 (0.0%) | 🟩 3 (0.0%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **928** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 7 (0.0%) | · | 🟩 725 (0.3%) | 🟩 564 (0.3%) | 🟩 240 (0.1%) | · | 🟩 712 (0.7%) | 🟩 691 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **744** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 44 (0.0%) | · | 🟩 23 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **509** | · | · | · |
| **16** | · | · | 🟩 372 (0.2%) | 🟩 111 (0.1%) | 🟩 24 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **373** | · | · |
| **17** | 🟩 100 (0.0%) | · | 🟩 103 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | 🟩 1 (0.0%) | 🟩 258 (0.3%) | 🟩 54 (0.1%) | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **16** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 2,548,334 |
| 2 | HaGeZi's Gambling Blocklist | 580,020 |
| 3 | HaGeZi's Ultimate Blocklist | 234,909 |
| 4 | CHN: AdRules DNS List | 193,660 |
| 5 | AdGuard DNS filter | 175,430 |
| 6 | Phishing Army | 122,672 |
| 7 | CHN: anti-AD | 99,387 |
| 8 | OISD Blocklist Small | 56,697 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 33,773 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,832 |
| 11 | Malicious URL Blocklist (URLHaus) | 2,506 |
| 12 | ShadowWhisperer's Dating List | 1,376 |
| 13 | Scam Blocklist by DurableNapkin | 928 |
| 14 | AWAvenue Ads Rule | 744 |
| 15 | Stalkerware Indicators List | 509 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 373 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 16 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 162,749 | 🟧 78.9% | 92.8% | 84.0% |
| CHN: anti-AD | CHN: AdRules DNS List | 85,791 | 🟨 41.4% | 86.3% | 44.3% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 80,393 | 🟨 23.1% | 41.5% | 34.2% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 79,545 | 🟨 24.0% | 45.3% | 33.9% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 78,648 | 🟩 2.9% | 3.1% | 33.5% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 77,086 | 🟩 3.0% | 62.8% | 3.0% |
| AdGuard DNS filter | CHN: anti-AD | 76,507 | 🟨 38.6% | 43.6% | 77.0% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 58,465 | 🟨 21.2% | 58.8% | 24.9% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 56,616 | 🟨 24.1% | 24.1% | 99.9% |
| CHN: AdRules DNS List | OISD Blocklist Small | 53,084 | 🟨 26.9% | 27.4% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 52,533 | 🟨 29.3% | 29.9% | 92.7% |
| CHN: anti-AD | OISD Blocklist Small | 40,934 | 🟨 35.5% | 41.2% | 72.2% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 18,885 | 🟩 13.7% | 15.4% | 55.9% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 14,127 | 🟩 0.5% | 7.3% | 0.6% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 12,441 | 🟩 0.5% | 7.1% | 0.5% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 10,228 | 🟩 0.4% | 0.4% | 18.0% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 9,613 | 🟩 0.4% | 9.7% | 0.4% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 7,374 | 🟩 0.3% | 21.8% | 0.3% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 6,930 | 🟩 2.0% | 5.6% | 3.0% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 5,532 | 🟩 0.2% | 0.2% | 1.0% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,550,923 | 2,548,334 | 0.1% |
| HaGeZi's Gambling Blocklist | 580,044 | 580,020 | 0.0% |
| HaGeZi's Ultimate Blocklist | 236,129 | 234,909 | 0.5% |
| CHN: AdRules DNS List | 197,482 | 193,660 | 1.9% |
| AdGuard DNS filter | 177,716 | 175,430 | 1.3% |
| Phishing Army | 145,091 | 122,672 | 15.5% |
| CHN: anti-AD | 100,094 | 99,387 | 0.7% |
| OISD Blocklist Small | 58,132 | 56,697 | 2.5% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 37,324 | 33,773 | 9.5% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,092 | 15,832 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 3,128 | 2,506 | 19.9% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 0.0% |
| Scam Blocklist by DurableNapkin | 931 | 928 | 0.3% |
| AWAvenue Ads Rule | 898 | 744 | 17.1% |
| Stalkerware Indicators List | 928 | 509 | 45.2% |
| HaGeZi's Windows/Office Tracker Blocklist | 381 | 373 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, CHN: anti-AD, OISD Blocklist Small, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 八层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → DNSBL(Spamhaus DBL + SURBL) → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：8
- 🟢 安全：53
- ⚪ 未知：0

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 0 |
| URLhaus | 恶意软件分发域名 | ✅ 启用 | 免费 | 0 |
| ThreatFox | C2 命令控制域名 | ✅ 启用 | 免费 | 0 |
| RDAP 域名年龄 | 新注册域名<30天标记 | ✅ 启用 | 免费 | 0 |
| MarketNow 诈骗检测 | 拼写劫持/可疑TLD/未注册 | ✅ 启用 | 免费 | 0 |
| VirusTotal | 多引擎厂商信誉 | ⬜ 未启用 | 需API Key | - |
| AI/LLM 分类 | 低置信度域名语义分类 | ⬜ 未启用 | 需API Key | - |

### 白名单域名类别分布

| 类别 | 数量 | 占比 |
|------|------|------|
| 广告/营销 | 3 | 4.9% |
| 分析/追踪 | 3 | 4.9% |
| CDN/基础设施 | 1 | 1.6% |
| 微软/Windows 遥测 | 10 | 16.4% |
| 社交/分享 | 3 | 4.9% |
| 电商/支付 | 3 | 4.9% |
| 隐私/安全 | 1 | 1.6% |
| 其他 | 37 | 60.7% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 20 | 32.8% |
| 中置信度 (子域名前缀) | 4 | 6.6% |
| 低置信度 (无法分类) | 37 | 60.7% |

| 域名 | 评级 | 类别 | 置信度 | 原因 | 来源 |
|------|------|------|--------|------|------|
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.12', '172.26.255.11', '172.26.255.1', '172.26.255.2'] | CHN: anti-AD |
| `dns.msftncsi.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['131.107.255.255', 'fd3e:4f5a:5b81::1'] | HaGeZi's DNS Rebind Protection |
| `edge-enterprise.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `edge.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `fritz.nas` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `meizu.coapi.moji.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | CHN: anti-AD |
| `news-app.abumedia.yql.yahoo.com` | 🟡 可疑 | 其他 | 0.00 | 诈骗/钓鱼检测 [SUSPICIOUS, 风险分45]: Domain NOT FOUND in the registry (RDAP 404) — likely unregistered. Any link using it is broken, fake or a typo; Deep subdomain chain (5 levels): common in phishing | CHN: anti-AD |
| `s.mvconf.f.360.cn` | 🟡 可疑 | 其他 | 0.00 | 诈骗/钓鱼检测 [SUSPICIOUS, 风险分45]: Domain NOT FOUND in the registry (RDAP 404) — likely unregistered. Any link using it is broken, fake or a typo; Deep subdomain chain (5 levels): common in phishing | CHN: anti-AD |
| `ad-block.dns.adguard.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-gone.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-putting.gw.zt-express.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.10010.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.abchina.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.azure.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.kazakinfo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.ourgame.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.siemens.com.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `adcdn.pingan.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ads.finance` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.privacy.qq.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.taboola.com` | 🟢 安全 | 广告/营销 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `advert.kf5.com` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `advertisement.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analysis.chess.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analysis.windows.net` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `api.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.huangye.miui.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `app-advertise.zhihuishu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.adjust.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `app.powerbi.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `autocomplete.clearbit.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `baozhang.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `buyad.bi-xenon.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `captcha.su.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `center-h5api.m.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `chart-embed.service.newrelic.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `counter-strike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `dxcloud.episerver.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `fritz.box` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `ftp.bmp.ovh` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `future.biz.weibo.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `img.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `msftconnecttest.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `passport.bobo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sdkapi.sms.mob.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `settings-win.data.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skyapi.onedrive.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skydrivesync.policies.live.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stat.jseea.cn` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.uptimerobot.com` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `storage.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tj.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.edu.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 3,478,090 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 1 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 62 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 63 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 72 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 7,035 |
| weebly.com | 4,137 |
| cloudfront.net | 3,440 |
| hl.cn | 3,311 |
| web.app | 2,047 |
| eu.cc | 2,008 |
| wixstudio.com | 1,998 |
| firebaseapp.com | 1,975 |
| amazonaws.com | 1,927 |
| pages.dev | 1,769 |
| r2.dev | 1,707 |
| sa.com | 1,191 |
| ru.com | 1,080 |
| my.id | 1,044 |
| run.app | 943 |
| vercel.app | 900 |
| framer.app | 832 |
| biz.id | 807 |
| dynu.org | 799 |
| aliyuncs.com | 716 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 51.1s |
| 源成功率 | 18/18 |
| 缓存命中 | 5 |
| 精确去重 | 584,806 |
| 规范化去重 | 4,529 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 38 |
| 模式丢弃 | 1,048 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 16.7 字符 |
| 最短/最长域名 | 2 / 164 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-10-05*
