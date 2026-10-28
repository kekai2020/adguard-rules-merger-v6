# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-10-28 05:16:04 | 源：18/18 | 缓存命中：8

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,947,535 |
| Allow 白名单 | 104 |
| 综合去重率 | 20.7% |
| 聚合精简 | 35,548 |
| 冲突消解 | 8 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 70.3s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,716,455 | - |
| 去重后（精确 730,166 / 规范化 3,088 / 正则 0） | 2,983,201 | -733,254 |
| 聚合后（精确 35,546 / 通配符 2 / 升级 0） | 2,947,653 | -35,548 |
| 冲突消解后 | 2,947,639 | -8 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,947,506 |
| ip | 72 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,095,816 |
| other | 502,718 |
| ads | 286,982 |
| phishing | 61,480 |
| tracking | 375 |
| mining | 164 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,096,622 | 2,094,685 | 99.9% | 1,801,836 | 292,849 | 86.0% |
| HaGeZi's Gambling Blocklist | 618,841 | 618,807 | 100.0% | 486,890 | 131,917 | 78.7% |
| HaGeZi's Ultimate Blocklist | 247,524 | 246,157 | 99.4% | 84,813 | 161,344 | 34.5% |
| Phishing Army | 152,911 | 131,234 | 85.8% | 43,099 | 88,135 | 32.8% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,262 | 15,999 | 98.4% | 14,538 | 1,461 | 90.9% |
| CHN: AdRules DNS List | 204,215 | 200,252 | 98.1% | 11,935 | 188,317 | 6.0% |
| CHN: anti-AD | 104,563 | 103,853 | 99.3% | 11,371 | 92,482 | 10.9% |
| AdGuard DNS filter | 184,004 | 181,581 | 98.7% | 4,953 | 176,628 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 25,350 | 23,448 | 92.5% | 2,474 | 20,974 | 10.6% |
| ShadowWhisperer's Dating List | 1,381 | 1,381 | 100.0% | 1,289 | 92 | 93.3% |
| Malicious URL Blocklist (URLHaus) | 1,808 | 1,720 | 95.1% | 609 | 1,111 | 35.4% |
| Stalkerware Indicators List | 929 | 508 | 54.7% | 429 | 79 | 84.4% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 59,447 | 57,897 | 97.4% | 6 | 57,891 | 0.0% |
| Scam Blocklist by DurableNapkin | 937 | 934 | 99.7% | 4 | 930 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 97.9% | 1 | 374 | 0.3% |
| AWAvenue Ads Rule | 909 | 755 | 83.1% | 0 | 755 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **2,094,685** | 🟩 130,732 (5.1%) | 🟩 90,936 (4.0%) | 🟩 26,606 (1.2%) | 🟩 25,461 (1.1%) | 🟩 72,380 (3.4%) | 🟩 20,678 (0.9%) | 🟩 22,368 (1.1%) | 🟩 5,247 (0.2%) | 🟩 107 (0.0%) | 🟩 1,045 (0.0%) | 🟩 15 (0.0%) | 🟩 837 (0.0%) | 🟩 12 (0.0%) | 🟩 63 (0.0%) | · | 🟩 104 (0.0%) | · |
| **2** | 🟩 130,732 (5.1%) | **618,807** | 🟩 1,394 (0.2%) | 🟩 450 (0.1%) | 🟩 409 (0.1%) | 🟩 164 (0.0%) | 🟩 213 (0.0%) | 🟩 134 (0.0%) | 🟩 14 (0.0%) | 🟩 4 (0.0%) | 🟩 4 (0.0%) | · | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **3** | 🟩 90,936 (4.0%) | 🟩 1,394 (0.2%) | **246,157** | 🟨 81,172 (22.2%) | 🟨 80,104 (23.0%) | 🟩 6,141 (1.7%) | 🟨 60,604 (20.9%) | 🟨 57,745 (23.4%) | 🟩 800 (0.3%) | 🟩 1,413 (0.5%) | 🟩 139 (0.1%) | 🟩 77 (0.0%) | 🟩 374 (0.2%) | 🟩 735 (0.3%) | 🟩 22 (0.0%) | 🟩 374 (0.2%) | 🟩 102 (0.0%) | · |
| **4** | 🟩 26,606 (1.2%) | 🟩 450 (0.1%) | 🟨 81,172 (22.2%) | **200,252** | 🟧 168,942 (79.4%) | 🟩 31 (0.0%) | 🟨 85,039 (38.8%) | 🟨 54,218 (26.6%) | 🟩 33 (0.0%) | 🟩 84 (0.0%) | 🟩 10 (0.0%) | 🟩 35 (0.0%) | 🟩 930 (0.5%) | 🟩 565 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 25,461 (1.1%) | 🟩 409 (0.1%) | 🟨 80,104 (23.0%) | 🟧 168,942 (79.4%) | **181,581** | 🟩 21 (0.0%) | 🟨 75,383 (35.9%) | 🟨 53,655 (28.9%) | 🟩 25 (0.0%) | 🟩 34 (0.0%) | 🟩 3 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 240 (0.1%) | 🟩 2 (0.0%) | 🟩 24 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 72,380 (3.4%) | 🟩 164 (0.0%) | 🟩 6,141 (1.7%) | 🟩 31 (0.0%) | 🟩 21 (0.0%) | **131,234** | 🟩 10 (0.0%) | 🟩 8 (0.0%) | 🟩 20,285 (15.1%) | 🟩 13 (0.0%) | 🟩 12 (0.0%) | · | 🟩 5 (0.0%) | · | · | · | · | · |
| **7** | 🟩 20,678 (0.9%) | 🟩 213 (0.0%) | 🟨 60,604 (20.9%) | 🟨 85,039 (38.8%) | 🟨 75,383 (35.9%) | 🟩 10 (0.0%) | **103,853** | 🟨 41,008 (34.0%) | 🟩 24 (0.0%) | 🟩 30 (0.0%) | 🟩 468 (0.4%) | 🟩 25 (0.0%) | 🟩 10 (0.0%) | 🟩 721 (0.7%) | 🟩 5 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.2%) | · |
| **8** | 🟩 22,368 (1.1%) | 🟩 134 (0.0%) | 🟨 57,745 (23.4%) | 🟨 54,218 (26.6%) | 🟨 53,655 (28.9%) | 🟩 8 (0.0%) | 🟨 41,008 (34.0%) | **57,897** | 🟩 11 (0.0%) | 🟩 23 (0.0%) | 🟩 6 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 702 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 5,247 (0.2%) | 🟩 14 (0.0%) | 🟩 800 (0.3%) | 🟩 33 (0.0%) | 🟩 25 (0.0%) | 🟩 20,285 (15.1%) | 🟩 24 (0.0%) | 🟩 11 (0.0%) | **23,448** | 🟩 11 (0.0%) | 🟩 13 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 107 (0.0%) | 🟩 4 (0.0%) | 🟩 1,413 (0.5%) | 🟩 84 (0.0%) | 🟩 34 (0.0%) | 🟩 13 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 11 (0.0%) | **15,999** | 🟩 6 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,045 (0.0%) | 🟩 4 (0.0%) | 🟩 139 (0.1%) | 🟩 10 (0.0%) | 🟩 3 (0.0%) | 🟩 12 (0.0%) | 🟩 468 (0.4%) | 🟩 6 (0.0%) | 🟩 13 (0.1%) | 🟩 6 (0.0%) | **1,720** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · |
| **12** | 🟩 15 (0.0%) | · | 🟩 77 (0.0%) | 🟩 35 (0.0%) | 🟩 30 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,381** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 837 (0.0%) | 🟩 3 (0.0%) | 🟩 374 (0.2%) | 🟩 930 (0.5%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **934** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 12 (0.0%) | · | 🟩 735 (0.3%) | 🟩 565 (0.3%) | 🟩 240 (0.1%) | · | 🟩 721 (0.7%) | 🟩 702 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **755** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 63 (0.0%) | 🟩 1 (0.0%) | 🟩 22 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **508** | · | · | · |
| **16** | · | · | 🟩 374 (0.2%) | 🟩 111 (0.1%) | 🟩 24 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **375** | · | · |
| **17** | 🟩 104 (0.0%) | · | 🟩 102 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.2%) | 🟩 54 (0.1%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.1%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 2,094,685 |
| 2 | HaGeZi's Gambling Blocklist | 618,807 |
| 3 | HaGeZi's Ultimate Blocklist | 246,157 |
| 4 | CHN: AdRules DNS List | 200,252 |
| 5 | AdGuard DNS filter | 181,581 |
| 6 | Phishing Army | 131,234 |
| 7 | CHN: anti-AD | 103,853 |
| 8 | OISD Blocklist Small | 57,897 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 23,448 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,999 |
| 11 | Malicious URL Blocklist (URLHaus) | 1,720 |
| 12 | ShadowWhisperer's Dating List | 1,381 |
| 13 | Scam Blocklist by DurableNapkin | 934 |
| 14 | AWAvenue Ads Rule | 755 |
| 15 | Stalkerware Indicators List | 508 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 375 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 168,942 | 🟧 79.4% | 93.0% | 84.4% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 130,732 | 🟩 5.1% | 6.2% | 21.1% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 90,936 | 🟩 4.0% | 4.3% | 36.9% |
| CHN: anti-AD | CHN: AdRules DNS List | 85,039 | 🟨 38.8% | 81.9% | 42.5% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 81,172 | 🟨 22.2% | 40.5% | 33.0% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,104 | 🟨 23.0% | 44.1% | 32.5% |
| AdGuard DNS filter | CHN: anti-AD | 75,383 | 🟨 35.9% | 41.5% | 72.6% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,380 | 🟩 3.4% | 55.2% | 3.5% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 60,604 | 🟨 20.9% | 58.4% | 24.6% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 57,745 | 🟨 23.4% | 23.5% | 99.7% |
| CHN: AdRules DNS List | OISD Blocklist Small | 54,218 | 🟨 26.6% | 27.1% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 53,655 | 🟨 28.9% | 29.5% | 92.7% |
| CHN: anti-AD | OISD Blocklist Small | 41,008 | 🟨 34.0% | 39.5% | 70.8% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 26,606 | 🟩 1.2% | 13.3% | 1.3% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 25,461 | 🟩 1.1% | 14.0% | 1.2% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 22,368 | 🟩 1.1% | 1.1% | 38.6% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 20,678 | 🟩 0.9% | 19.9% | 1.0% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 20,285 | 🟩 15.1% | 15.5% | 86.5% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 6,141 | 🟩 1.7% | 4.7% | 2.5% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 5,247 | 🟩 0.2% | 22.4% | 0.3% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,096,622 | 2,094,685 | 0.1% |
| HaGeZi's Gambling Blocklist | 618,841 | 618,807 | 0.0% |
| HaGeZi's Ultimate Blocklist | 247,524 | 246,157 | 0.6% |
| CHN: AdRules DNS List | 204,215 | 200,252 | 1.9% |
| AdGuard DNS filter | 184,004 | 181,581 | 1.3% |
| Phishing Army | 152,911 | 131,234 | 14.2% |
| CHN: anti-AD | 104,563 | 103,853 | 0.7% |
| OISD Blocklist Small | 59,447 | 57,897 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 25,350 | 23,448 | 7.5% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,262 | 15,999 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 1,808 | 1,720 | 4.9% |
| ShadowWhisperer's Dating List | 1,381 | 1,381 | 0.0% |
| Scam Blocklist by DurableNapkin | 937 | 934 | 0.3% |
| AWAvenue Ads Rule | 909 | 755 | 16.9% |
| Stalkerware Indicators List | 929 | 508 | 45.3% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `ad.cityu.edu.hk` | `||ad.cityu.edu.hk^` | HaGeZi's Ultimate Blocklist | `@@||ad.cityu.edu.hk^` | CHN: anti-AD | 精确 |
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
- 🟡 可疑：15
- 🟢 安全：86
- ⚪ 未知：2

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 15 |
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
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.1', '172.26.255.2', '172.26.255.12', '172.26.255.11'] | CHN: anti-AD |
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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,947,506 |
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
| meusitehostgator.com.br | 3,149 |
| cloudfront.net | 3,068 |
| pages.dev | 2,610 |
| wixstudio.com | 2,379 |
| eu.cc | 2,321 |
| weebly.com | 2,308 |
| web.app | 2,018 |
| firebaseapp.com | 1,926 |
| hl.cn | 1,848 |
| amazonaws.com | 1,643 |
| r2.dev | 1,431 |
| vercel.app | 1,246 |
| run.app | 1,068 |
| sa.com | 876 |
| ru.com | 832 |
| co.com | 696 |
| blogspot.com | 692 |
| allserial.icu | 639 |
| dynu.org | 601 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 70.3s |
| 源成功率 | 18/18 |
| 缓存命中 | 8 |
| 精确去重 | 730,166 |
| 规范化去重 | 3,088 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,037 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.0 字符 |
| 最短/最长域名 | 2 / 242 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-10-28*
