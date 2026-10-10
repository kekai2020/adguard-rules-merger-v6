# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-10-10 05:30:39 | 源：18/18 | 缓存命中：6

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,906,920 |
| Allow 白名单 | 104 |
| 综合去重率 | 17.9% |
| 聚合精简 | 36,479 |
| 冲突消解 | 7 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 51.2s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,540,674 | - |
| 去重后（精确 593,507 / 规范化 3,651 / 正则 0） | 2,943,516 | -597,158 |
| 聚合后（精确 36,477 / 通配符 2 / 升级 0） | 2,907,037 | -36,479 |
| 冲突消解后 | 2,907,024 | -7 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,906,889 |
| ip | 72 |
| regex | 62 |
| wildcard | 1 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 1,983,637 |
| other | 592,811 |
| ads | 268,754 |
| phishing | 61,171 |
| tracking | 375 |
| mining | 172 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,983,900 | 1,982,078 | 99.9% | 1,815,835 | 166,243 | 91.6% |
| HaGeZi's Gambling Blocklist | 582,596 | 582,572 | 100.0% | 577,695 | 4,877 | 99.2% |
| HaGeZi's Ultimate Blocklist | 231,171 | 229,903 | 99.5% | 76,247 | 153,656 | 33.2% |
| Phishing Army | 142,545 | 120,713 | 84.7% | 35,960 | 84,753 | 29.8% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,562 | 15,302 | 98.3% | 13,830 | 1,472 | 90.4% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 34,768 | 31,616 | 90.9% | 13,257 | 18,359 | 41.9% |
| CHN: AdRules DNS List | 201,067 | 197,180 | 98.1% | 11,731 | 185,449 | 5.9% |
| CHN: anti-AD | 100,094 | 99,387 | 99.3% | 7,720 | 91,667 | 7.8% |
| AdGuard DNS filter | 180,979 | 178,649 | 98.7% | 4,979 | 173,670 | 2.8% |
| ShadowWhisperer's Dating List | 1,378 | 1,378 | 100.0% | 1,286 | 92 | 93.3% |
| Malicious URL Blocklist (URLHaus) | 2,819 | 2,340 | 83.0% | 995 | 1,345 | 42.5% |
| Stalkerware Indicators List | 928 | 509 | 54.8% | 450 | 59 | 88.4% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 60,284 | 58,810 | 97.6% | 12 | 58,798 | 0.0% |
| Scam Blocklist by DurableNapkin | 933 | 930 | 99.7% | 11 | 919 | 1.2% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 97.9% | 1 | 374 | 0.3% |
| AWAvenue Ads Rule | 898 | 745 | 83.0% | 0 | 745 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,982,078** | 🟩 3,783 (0.1%) | 🟩 87,596 (4.1%) | 🟩 28,023 (1.3%) | 🟩 26,600 (1.2%) | 🟩 73,007 (3.6%) | 🟩 21,218 (1.0%) | 🟩 23,434 (1.2%) | 🟩 6,537 (0.3%) | 🟩 121 (0.0%) | 🟩 1,259 (0.1%) | 🟩 14 (0.0%) | 🟩 821 (0.0%) | 🟩 11 (0.0%) | 🟩 42 (0.0%) | · | 🟩 96 (0.0%) | · |
| **2** | 🟩 3,783 (0.1%) | **582,572** | 🟩 1,422 (0.2%) | 🟩 426 (0.1%) | 🟩 387 (0.1%) | 🟩 151 (0.0%) | 🟩 201 (0.0%) | 🟩 126 (0.0%) | 🟩 12 (0.0%) | 🟩 2 (0.0%) | 🟩 14 (0.0%) | · | 🟩 2 (0.0%) | · | · | · | · | · |
| **3** | 🟩 87,596 (4.1%) | 🟩 1,422 (0.2%) | **229,903** | 🟨 79,560 (22.9%) | 🟨 78,648 (23.8%) | 🟩 3,536 (1.0%) | 🟨 57,621 (21.2%) | 🟨 57,978 (25.1%) | 🟩 780 (0.3%) | 🟩 1,416 (0.6%) | 🟩 107 (0.0%) | 🟩 79 (0.0%) | 🟩 360 (0.2%) | 🟩 726 (0.3%) | 🟩 23 (0.0%) | 🟩 374 (0.2%) | 🟩 99 (0.0%) | · |
| **4** | 🟩 28,023 (1.3%) | 🟩 426 (0.1%) | 🟨 79,560 (22.9%) | **197,180** | 🟧 165,994 (79.1%) | 🟩 24 (0.0%) | 🟨 85,771 (40.7%) | 🟨 55,174 (27.5%) | 🟩 31 (0.0%) | 🟩 80 (0.0%) | 🟩 11 (0.0%) | 🟩 34 (0.0%) | 🟩 918 (0.5%) | 🟩 564 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 26,600 (1.2%) | 🟩 387 (0.1%) | 🟨 78,648 (23.8%) | 🟧 165,994 (79.1%) | **178,649** | 🟩 14 (0.0%) | 🟨 76,253 (37.8%) | 🟨 54,626 (29.9%) | 🟩 21 (0.0%) | 🟩 30 (0.0%) | 🟩 4 (0.0%) | 🟩 29 (0.0%) | 🟩 21 (0.0%) | 🟩 240 (0.1%) | 🟩 2 (0.0%) | 🟩 24 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 73,007 (3.6%) | 🟩 151 (0.0%) | 🟩 3,536 (1.0%) | 🟩 24 (0.0%) | 🟩 14 (0.0%) | **120,713** | 🟩 11 (0.0%) | 🟩 7 (0.0%) | 🟩 17,470 (13.0%) | 🟩 12 (0.0%) | 🟩 14 (0.0%) | · | 🟩 3 (0.0%) | · | · | · | · | · |
| **7** | 🟩 21,218 (1.0%) | 🟩 201 (0.0%) | 🟨 57,621 (21.2%) | 🟨 85,771 (40.7%) | 🟨 76,253 (37.8%) | 🟩 11 (0.0%) | **99,387** | 🟨 40,570 (34.5%) | 🟩 24 (0.0%) | 🟩 30 (0.0%) | 🟩 426 (0.4%) | 🟩 25 (0.0%) | 🟩 10 (0.0%) | 🟩 713 (0.7%) | 🟩 5 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 23,434 (1.2%) | 🟩 126 (0.0%) | 🟨 57,978 (25.1%) | 🟨 55,174 (27.5%) | 🟨 54,626 (29.9%) | 🟩 7 (0.0%) | 🟨 40,570 (34.5%) | **58,810** | 🟩 11 (0.0%) | 🟩 21 (0.0%) | 🟩 6 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 692 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 55 (0.1%) | · |
| **9** | 🟩 6,537 (0.3%) | 🟩 12 (0.0%) | 🟩 780 (0.3%) | 🟩 31 (0.0%) | 🟩 21 (0.0%) | 🟩 17,470 (13.0%) | 🟩 24 (0.0%) | 🟩 11 (0.0%) | **31,616** | 🟩 11 (0.0%) | 🟩 25 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 121 (0.0%) | 🟩 2 (0.0%) | 🟩 1,416 (0.6%) | 🟩 80 (0.0%) | 🟩 30 (0.0%) | 🟩 12 (0.0%) | 🟩 30 (0.0%) | 🟩 21 (0.0%) | 🟩 11 (0.0%) | **15,302** | 🟩 7 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,259 (0.1%) | 🟩 14 (0.0%) | 🟩 107 (0.0%) | 🟩 11 (0.0%) | 🟩 4 (0.0%) | 🟩 14 (0.0%) | 🟩 426 (0.4%) | 🟩 6 (0.0%) | 🟩 25 (0.1%) | 🟩 7 (0.0%) | **2,340** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 14 (0.0%) | · | 🟩 79 (0.0%) | 🟩 34 (0.0%) | 🟩 29 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,378** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 821 (0.0%) | 🟩 2 (0.0%) | 🟩 360 (0.2%) | 🟩 918 (0.5%) | 🟩 21 (0.0%) | 🟩 3 (0.0%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **930** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 11 (0.0%) | · | 🟩 726 (0.3%) | 🟩 564 (0.3%) | 🟩 240 (0.1%) | · | 🟩 713 (0.7%) | 🟩 692 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **745** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 42 (0.0%) | · | 🟩 23 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **509** | · | · | · |
| **16** | · | · | 🟩 374 (0.2%) | 🟩 111 (0.1%) | 🟩 24 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **375** | · | · |
| **17** | 🟩 96 (0.0%) | · | 🟩 99 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 55 (0.1%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,982,078 |
| 2 | HaGeZi's Gambling Blocklist | 582,572 |
| 3 | HaGeZi's Ultimate Blocklist | 229,903 |
| 4 | CHN: AdRules DNS List | 197,180 |
| 5 | AdGuard DNS filter | 178,649 |
| 6 | Phishing Army | 120,713 |
| 7 | CHN: anti-AD | 99,387 |
| 8 | OISD Blocklist Small | 58,810 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 31,616 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,302 |
| 11 | Malicious URL Blocklist (URLHaus) | 2,340 |
| 12 | ShadowWhisperer's Dating List | 1,378 |
| 13 | Scam Blocklist by DurableNapkin | 930 |
| 14 | AWAvenue Ads Rule | 745 |
| 15 | Stalkerware Indicators List | 509 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 375 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 165,994 | 🟧 79.1% | 92.9% | 84.2% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 87,596 | 🟩 4.1% | 4.4% | 38.1% |
| CHN: anti-AD | CHN: AdRules DNS List | 85,771 | 🟨 40.7% | 86.3% | 43.5% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 79,560 | 🟨 22.9% | 40.3% | 34.6% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 78,648 | 🟨 23.8% | 44.0% | 34.2% |
| AdGuard DNS filter | CHN: anti-AD | 76,253 | 🟨 37.8% | 42.7% | 76.7% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 73,007 | 🟩 3.6% | 60.5% | 3.7% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 57,978 | 🟨 25.1% | 25.2% | 98.6% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 57,621 | 🟨 21.2% | 58.0% | 25.1% |
| CHN: AdRules DNS List | OISD Blocklist Small | 55,174 | 🟨 27.5% | 28.0% | 93.8% |
| AdGuard DNS filter | OISD Blocklist Small | 54,626 | 🟨 29.9% | 30.6% | 92.9% |
| CHN: anti-AD | OISD Blocklist Small | 40,570 | 🟨 34.5% | 40.8% | 69.0% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 28,023 | 🟩 1.3% | 14.2% | 1.4% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 26,600 | 🟩 1.2% | 14.9% | 1.3% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 23,434 | 🟩 1.2% | 1.2% | 39.8% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 21,218 | 🟩 1.0% | 21.3% | 1.1% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 17,470 | 🟩 13.0% | 14.5% | 55.3% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 6,537 | 🟩 0.3% | 20.7% | 0.3% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 3,783 | 🟩 0.1% | 0.2% | 0.6% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 3,536 | 🟩 1.0% | 2.9% | 1.5% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,983,900 | 1,982,078 | 0.1% |
| HaGeZi's Gambling Blocklist | 582,596 | 582,572 | 0.0% |
| HaGeZi's Ultimate Blocklist | 231,171 | 229,903 | 0.5% |
| CHN: AdRules DNS List | 201,067 | 197,180 | 1.9% |
| AdGuard DNS filter | 180,979 | 178,649 | 1.3% |
| Phishing Army | 142,545 | 120,713 | 15.3% |
| CHN: anti-AD | 100,094 | 99,387 | 0.7% |
| OISD Blocklist Small | 60,284 | 58,810 | 2.4% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 34,768 | 31,616 | 9.1% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,562 | 15,302 | 1.7% |
| Malicious URL Blocklist (URLHaus) | 2,819 | 2,340 | 17.0% |
| ShadowWhisperer's Dating List | 1,378 | 1,378 | 0.0% |
| Scam Blocklist by DurableNapkin | 933 | 930 | 0.3% |
| AWAvenue Ads Rule | 898 | 745 | 17.0% |
| Stalkerware Indicators List | 928 | 509 | 45.2% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, CHN: anti-AD, OISD Blocklist Small, HaGeZi's Ultimate Blocklist, CHN: AdRules DNS List | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 八层防御体系：DNS解析 → URLhaus/ThreatFox威胁情报 → RDAP域名年龄 → MarketNow诈骗检测 → DNSBL(Spamhaus DBL + SURBL) → VirusTotal(可选) → 离线PSL分类 → AI语义分类(可选)。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：16
- 🟢 安全：85
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
| `news-app.abumedia.yql.yahoo.com` | 🟡 可疑 | 其他 | 0.00 | 诈骗/钓鱼检测 [SUSPICIOUS, 风险分45]: Domain NOT FOUND in the registry (RDAP 404) — likely unregistered. Any link using it is broken, fake or a typo; Deep subdomain chain (5 levels): common in phishing | CHN: anti-AD |
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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,906,889 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 1 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 104 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 62 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 72 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 7,024 |
| weebly.com | 3,710 |
| cloudfront.net | 3,415 |
| hl.cn | 3,177 |
| web.app | 2,033 |
| firebaseapp.com | 1,967 |
| eu.cc | 1,927 |
| wixstudio.com | 1,752 |
| pages.dev | 1,701 |
| amazonaws.com | 1,690 |
| r2.dev | 1,664 |
| sa.com | 1,153 |
| ru.com | 1,023 |
| run.app | 924 |
| vercel.app | 895 |
| framer.app | 728 |
| za.com | 691 |
| aliyuncs.com | 651 |
| my.id | 473 |
| co.com | 473 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 51.2s |
| 源成功率 | 18/18 |
| 缓存命中 | 6 |
| 精确去重 | 593,507 |
| 规范化去重 | 3,651 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,037 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.0 字符 |
| 最短/最长域名 | 2 / 137 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-10-10*
