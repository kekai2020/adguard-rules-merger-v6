# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-10-21 04:21:21 | 源：18/18 | 缓存命中：7

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,932,478 |
| Allow 白名单 | 104 |
| 综合去重率 | 19.7% |
| 聚合精简 | 34,906 |
| 冲突消解 | 9 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 39.5s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,652,580 | - |
| 去重后（精确 681,687 / 规范化 3,390 / 正则 0） | 2,967,503 | -685,077 |
| 聚合后（精确 34,903 / 通配符 3 / 升级 0） | 2,932,597 | -34,906 |
| 冲突消解后 | 2,932,582 | -9 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,932,449 |
| ip | 72 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,040,803 |
| other | 545,264 |
| ads | 282,382 |
| phishing | 63,489 |
| tracking | 375 |
| mining | 165 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,040,214 | 2,039,421 | 100.0% | 1,803,920 | 235,501 | 88.5% |
| HaGeZi's Gambling Blocklist | 602,532 | 602,509 | 100.0% | 529,437 | 73,072 | 87.9% |
| HaGeZi's Ultimate Blocklist | 242,745 | 241,341 | 99.4% | 81,368 | 159,973 | 33.7% |
| Phishing Army | 155,842 | 133,467 | 85.6% | 42,528 | 90,939 | 31.9% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,282 | 16,007 | 98.3% | 14,541 | 1,466 | 90.8% |
| CHN: AdRules DNS List | 209,632 | 205,678 | 98.1% | 11,740 | 193,938 | 5.7% |
| CHN: anti-AD | 103,050 | 102,332 | 99.3% | 7,635 | 94,697 | 7.5% |
| AdGuard DNS filter | 189,369 | 186,969 | 98.7% | 4,938 | 182,031 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 28,606 | 26,277 | 91.9% | 2,350 | 23,927 | 8.9% |
| ShadowWhisperer's Dating List | 1,379 | 1,379 | 100.0% | 1,285 | 94 | 93.2% |
| Malicious URL Blocklist (URLHaus) | 1,988 | 1,901 | 95.6% | 825 | 1,076 | 43.4% |
| Stalkerware Indicators List | 929 | 510 | 54.9% | 454 | 56 | 89.0% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 57,404 | 55,860 | 97.3% | 7 | 55,853 | 0.0% |
| Scam Blocklist by DurableNapkin | 958 | 955 | 99.7% | 4 | 951 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 97.9% | 1 | 374 | 0.3% |
| AWAvenue Ads Rule | 898 | 745 | 83.0% | 0 | 745 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **2,039,421** | 🟩 71,940 (2.8%) | 🟩 91,306 (4.2%) | 🟩 27,942 (1.3%) | 🟩 26,553 (1.2%) | 🟩 72,503 (3.5%) | 🟩 21,299 (1.0%) | 🟩 22,167 (1.1%) | 🟩 5,530 (0.3%) | 🟩 109 (0.0%) | 🟩 1,000 (0.0%) | 🟩 14 (0.0%) | 🟩 842 (0.0%) | 🟩 11 (0.0%) | 🟩 40 (0.0%) | · | 🟩 103 (0.0%) | · |
| **2** | 🟩 71,940 (2.8%) | **602,509** | 🟩 1,359 (0.2%) | 🟩 440 (0.1%) | 🟩 401 (0.1%) | 🟩 153 (0.0%) | 🟩 207 (0.0%) | 🟩 131 (0.0%) | 🟩 11 (0.0%) | 🟩 4 (0.0%) | 🟩 4 (0.0%) | · | 🟩 3 (0.0%) | · | · | · | · | · |
| **3** | 🟩 91,306 (4.2%) | 🟩 1,359 (0.2%) | **241,341** | 🟨 81,920 (22.4%) | 🟨 80,870 (23.3%) | 🟩 5,468 (1.5%) | 🟨 59,850 (21.1%) | 🟨 55,643 (23.0%) | 🟩 831 (0.3%) | 🟩 1,413 (0.6%) | 🟩 115 (0.0%) | 🟩 80 (0.0%) | 🟩 372 (0.2%) | 🟩 726 (0.3%) | 🟩 22 (0.0%) | 🟩 374 (0.2%) | 🟩 103 (0.0%) | · |
| **4** | 🟩 27,942 (1.3%) | 🟩 440 (0.1%) | 🟨 81,920 (22.4%) | **205,678** | 🟧 174,339 (79.9%) | 🟩 33 (0.0%) | 🟨 88,722 (40.5%) | 🟨 52,208 (24.9%) | 🟩 30 (0.0%) | 🟩 82 (0.0%) | 🟩 11 (0.0%) | 🟩 35 (0.0%) | 🟩 951 (0.5%) | 🟩 563 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 26,553 (1.2%) | 🟩 401 (0.1%) | 🟨 80,870 (23.3%) | 🟧 174,339 (79.9%) | **186,969** | 🟩 22 (0.0%) | 🟨 79,139 (37.7%) | 🟨 51,646 (27.0%) | 🟩 22 (0.0%) | 🟩 32 (0.0%) | 🟩 4 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 239 (0.1%) | 🟩 2 (0.0%) | 🟩 24 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 72,503 (3.5%) | 🟩 153 (0.0%) | 🟩 5,468 (1.5%) | 🟩 33 (0.0%) | 🟩 22 (0.0%) | **133,467** | 🟩 11 (0.0%) | 🟩 9 (0.0%) | 🟩 23,252 (17.0%) | 🟩 14 (0.0%) | 🟩 16 (0.0%) | · | 🟩 4 (0.0%) | · | · | · | · | · |
| **7** | 🟩 21,299 (1.0%) | 🟩 207 (0.0%) | 🟨 59,850 (21.1%) | 🟨 88,722 (40.5%) | 🟨 79,139 (37.7%) | 🟩 11 (0.0%) | **102,332** | 🟨 40,278 (34.2%) | 🟩 24 (0.0%) | 🟩 31 (0.0%) | 🟩 465 (0.4%) | 🟩 25 (0.0%) | 🟩 10 (0.0%) | 🟩 713 (0.7%) | 🟩 5 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 22,167 (1.1%) | 🟩 131 (0.0%) | 🟨 55,643 (23.0%) | 🟨 52,208 (24.9%) | 🟨 51,646 (27.0%) | 🟩 9 (0.0%) | 🟨 40,278 (34.2%) | **55,860** | 🟩 11 (0.0%) | 🟩 23 (0.0%) | 🟩 7 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 692 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 5,530 (0.3%) | 🟩 11 (0.0%) | 🟩 831 (0.3%) | 🟩 30 (0.0%) | 🟩 22 (0.0%) | 🟩 23,252 (17.0%) | 🟩 24 (0.0%) | 🟩 11 (0.0%) | **26,277** | 🟩 12 (0.0%) | 🟩 17 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 109 (0.0%) | 🟩 4 (0.0%) | 🟩 1,413 (0.6%) | 🟩 82 (0.0%) | 🟩 32 (0.0%) | 🟩 14 (0.0%) | 🟩 31 (0.0%) | 🟩 23 (0.0%) | 🟩 12 (0.0%) | **16,007** | 🟩 7 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,000 (0.0%) | 🟩 4 (0.0%) | 🟩 115 (0.0%) | 🟩 11 (0.0%) | 🟩 4 (0.0%) | 🟩 16 (0.0%) | 🟩 465 (0.4%) | 🟩 7 (0.0%) | 🟩 17 (0.1%) | 🟩 7 (0.0%) | **1,901** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 14 (0.0%) | · | 🟩 80 (0.0%) | 🟩 35 (0.0%) | 🟩 30 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,379** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 842 (0.0%) | 🟩 3 (0.0%) | 🟩 372 (0.2%) | 🟩 951 (0.5%) | 🟩 23 (0.0%) | 🟩 4 (0.0%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **955** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 11 (0.0%) | · | 🟩 726 (0.3%) | 🟩 563 (0.3%) | 🟩 239 (0.1%) | · | 🟩 713 (0.7%) | 🟩 692 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **745** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 40 (0.0%) | · | 🟩 22 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **510** | · | · | · |
| **16** | · | · | 🟩 374 (0.2%) | 🟩 111 (0.1%) | 🟩 24 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **375** | · | · |
| **17** | 🟩 103 (0.0%) | · | 🟩 103 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 54 (0.1%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 2,039,421 |
| 2 | HaGeZi's Gambling Blocklist | 602,509 |
| 3 | HaGeZi's Ultimate Blocklist | 241,341 |
| 4 | CHN: AdRules DNS List | 205,678 |
| 5 | AdGuard DNS filter | 186,969 |
| 6 | Phishing Army | 133,467 |
| 7 | CHN: anti-AD | 102,332 |
| 8 | OISD Blocklist Small | 55,860 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 26,277 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,007 |
| 11 | Malicious URL Blocklist (URLHaus) | 1,901 |
| 12 | ShadowWhisperer's Dating List | 1,379 |
| 13 | Scam Blocklist by DurableNapkin | 955 |
| 14 | AWAvenue Ads Rule | 745 |
| 15 | Stalkerware Indicators List | 510 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 375 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 174,339 | 🟧 79.9% | 93.2% | 84.8% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 91,306 | 🟩 4.2% | 4.5% | 37.8% |
| CHN: anti-AD | CHN: AdRules DNS List | 88,722 | 🟨 40.5% | 86.7% | 43.1% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 81,920 | 🟨 22.4% | 39.8% | 33.9% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,870 | 🟨 23.3% | 43.3% | 33.5% |
| AdGuard DNS filter | CHN: anti-AD | 79,139 | 🟨 37.7% | 42.3% | 77.3% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,503 | 🟩 3.5% | 54.3% | 3.6% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 71,940 | 🟩 2.8% | 3.5% | 11.9% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 59,850 | 🟨 21.1% | 58.5% | 24.8% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 55,643 | 🟨 23.0% | 23.1% | 99.6% |
| CHN: AdRules DNS List | OISD Blocklist Small | 52,208 | 🟨 24.9% | 25.4% | 93.5% |
| AdGuard DNS filter | OISD Blocklist Small | 51,646 | 🟨 27.0% | 27.6% | 92.5% |
| CHN: anti-AD | OISD Blocklist Small | 40,278 | 🟨 34.2% | 39.4% | 72.1% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 27,942 | 🟩 1.3% | 13.6% | 1.4% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 26,553 | 🟩 1.2% | 14.2% | 1.3% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 23,252 | 🟩 17.0% | 17.4% | 88.5% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 22,167 | 🟩 1.1% | 1.1% | 39.7% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 21,299 | 🟩 1.0% | 20.8% | 1.0% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 5,530 | 🟩 0.3% | 21.0% | 0.3% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 5,468 | 🟩 1.5% | 4.1% | 2.3% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,040,214 | 2,039,421 | 0.0% |
| HaGeZi's Gambling Blocklist | 602,532 | 602,509 | 0.0% |
| HaGeZi's Ultimate Blocklist | 242,745 | 241,341 | 0.6% |
| CHN: AdRules DNS List | 209,632 | 205,678 | 1.9% |
| AdGuard DNS filter | 189,369 | 186,969 | 1.3% |
| Phishing Army | 155,842 | 133,467 | 14.4% |
| CHN: anti-AD | 103,050 | 102,332 | 0.7% |
| OISD Blocklist Small | 57,404 | 55,860 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 28,606 | 26,277 | 8.1% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,282 | 16,007 | 1.7% |
| Malicious URL Blocklist (URLHaus) | 1,988 | 1,901 | 4.4% |
| ShadowWhisperer's Dating List | 1,379 | 1,379 | 0.0% |
| Scam Blocklist by DurableNapkin | 958 | 955 | 0.3% |
| AWAvenue Ads Rule | 898 | 745 | 17.0% |
| Stalkerware Indicators List | 929 | 510 | 45.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `supportmalerschwab.direct.quickconnect.to` | `||supportmalerschwab.direct.quickconnect.to^` | Phishing Army | `@@||direct.quickconnect.to^` | HaGeZi's DNS Rebind Protection | 级联 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `ad.cityu.edu.hk` | `||ad.cityu.edu.hk^` | HaGeZi's Ultimate Blocklist | `@@||ad.cityu.edu.hk^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | OISD Blocklist Small, AWAvenue Ads Rule, HaGeZi's Ultimate Blocklist, CHN: anti-AD, CHN: AdRules DNS List | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 八层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → DNSBL(Spamhaus DBL + SURBL) → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：15
- 🟢 安全：86
- ⚪ 未知：2

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
| 广告/营销 | 3 | 2.9% |
| 分析/追踪 | 3 | 2.9% |
| CDN/基础设施 | 1 | 1.0% |
| 微软/Windows 遥测 | 10 | 9.7% |
| 社交/分享 | 3 | 2.9% |
| 电商/支付 | 3 | 2.9% |
| 隐私/安全 | 7 | 6.8% |
| 其他 | 73 | 70.9% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 26 | 25.2% |
| 中置信度 (子域名前缀) | 4 | 3.9% |
| 低置信度 (无法分类) | 73 | 70.9% |

| 域名 | 评级 | 类别 | 置信度 | 原因 | 来源 |
|------|------|------|--------|------|------|
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.2', '172.26.255.12', '172.26.255.11', '172.26.255.1'] | CHN: anti-AD |
| `avqs.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `avts.mcafee.com` | 🟡 可疑 | 隐私/安全 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `dishy.starlink.com` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['192.168.100.1'] | HaGeZi's DNS Rebind Protection |
| `dns.msftncsi.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['131.107.255.255', 'fd3e:4f5a:5b81::1'] | HaGeZi's DNS Rebind Protection |
| `edge-enterprise.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `edge.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `fritz.nas` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.powerline` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.repeater` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.smartgateway` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `meizu.coapi.moji.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | CHN: anti-AD |
| `plex.direct` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['0.0.0.0'] | HaGeZi's DNS Rebind Protection |
| `router.asus.com` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `speedport.ip` | 🟡 可疑 | 其他 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `hash.cymru.com` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 (servfail)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `tplinklogin.net` | ⚪ 未知 | 其他 | 0.00 | 检测不完整：DNS 查询失败 (timeout)，威胁情报无有效命中 | HaGeZi's DNS Rebind Protection |
| `3gppnetwork.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
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
| `asusrouter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `autocomplete.clearbit.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `b.barracudacentral.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `backscatterer.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `baozhang.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `bl.blocklist.de` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `bl.spamcop.net` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `buyad.bi-xenon.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `captcha.su.baidu.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `center-h5api.m.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `chart-embed.service.newrelic.com` | 🟢 安全 | 分析/追踪 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `counter-strike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `direct.quickconnect.to` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnsbl.dronebl.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnswl.org` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dq.spamhaus.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dxcloud.episerver.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `fritz.box` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `ftp.bmp.ovh` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `future.biz.weibo.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `hostkarma.junkemailfilter.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `img.ads.tvb.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ipv4only.arpa` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `mail.abusix.zone` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `mailspike.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `msftconnecttest.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `myunraid.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `news-app.abumedia.yql.yahoo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `nordspam.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `passport.bobo.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `psbl.surriel.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `s.mvconf.f.360.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sdkapi.sms.mob.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `settings-win.data.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skyapi.onedrive.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skydrivesync.policies.live.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sophosxl.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spameatingmonkey.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamhaus.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamrats.com` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `stat.jseea.cn` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.uptimerobot.com` | 🟢 安全 | 分析/追踪 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `storage.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `surbl.org` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tj.gov.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.edu.cn` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tor.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `torexit.dan.me.uk` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkap.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkrepeater.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkwifi.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uceprotect.net` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uribl.com` | 🟢 安全 | 隐私/安全 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,932,449 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 104 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 61 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 72 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 7,023 |
| hl.cn | 3,886 |
| cloudfront.net | 2,941 |
| weebly.com | 2,808 |
| pages.dev | 2,662 |
| wixstudio.com | 2,492 |
| web.app | 2,029 |
| eu.cc | 1,981 |
| firebaseapp.com | 1,936 |
| amazonaws.com | 1,573 |
| r2.dev | 1,534 |
| vercel.app | 1,235 |
| run.app | 1,019 |
| blogspot.com | 713 |
| ru.com | 689 |
| allserial.icu | 639 |
| co.com | 638 |
| sa.com | 634 |
| googleapis.com | 550 |
| framer.app | 515 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 39.5s |
| 源成功率 | 18/18 |
| 缓存命中 | 7 |
| 精确去重 | 681,687 |
| 规范化去重 | 3,390 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,037 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 16.9 字符 |
| 最短/最长域名 | 2 / 242 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-10-21*
