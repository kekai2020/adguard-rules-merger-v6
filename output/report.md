# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-10-31 05:10:46 | 源：18/18 | 缓存命中：6

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,752,281 |
| Allow 白名单 | 104 |
| 综合去重率 | 21.6% |
| 聚合精简 | 36,108 |
| 冲突消解 | 7 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 54.2s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,510,426 | - |
| 去重后（精确 718,183 / 规范化 3,737 / 正则 0） | 2,788,506 | -721,920 |
| 聚合后（精确 36,106 / 通配符 2 / 升级 0） | 2,752,398 | -36,108 |
| 冲突消解后 | 2,752,385 | -7 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 2,752,252 |
| ip | 72 |
| regex | 61 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 1,852,063 |
| other | 521,539 |
| ads | 316,752 |
| phishing | 61,385 |
| tracking | 375 |
| mining | 167 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,852,751 | 1,850,846 | 99.9% | 1,589,057 | 261,789 | 85.9% |
| HaGeZi's Gambling Blocklist | 624,564 | 624,528 | 100.0% | 505,578 | 118,950 | 81.0% |
| HaGeZi's Ultimate Blocklist | 282,345 | 280,732 | 99.4% | 118,149 | 162,583 | 42.1% |
| Phishing Army | 152,865 | 130,959 | 85.7% | 41,373 | 89,586 | 31.6% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,378 | 16,115 | 98.4% | 14,673 | 1,442 | 91.1% |
| CHN: AdRules DNS List | 205,333 | 201,358 | 98.1% | 11,475 | 189,883 | 5.7% |
| CHN: anti-AD | 100,054 | 99,322 | 99.3% | 6,453 | 92,869 | 6.5% |
| AdGuard DNS filter | 185,104 | 182,670 | 98.7% | 4,852 | 177,818 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 24,081 | 22,342 | 92.8% | 1,314 | 21,028 | 5.9% |
| ShadowWhisperer's Dating List | 1,381 | 1,381 | 100.0% | 1,287 | 94 | 93.2% |
| Malicious URL Blocklist (URLHaus) | 1,862 | 1,772 | 95.2% | 480 | 1,292 | 27.1% |
| Stalkerware Indicators List | 929 | 508 | 54.7% | 442 | 66 | 87.0% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 60,181 | 58,622 | 97.4% | 6 | 58,616 | 0.0% |
| Scam Blocklist by DurableNapkin | 937 | 934 | 99.7% | 4 | 930 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 383 | 375 | 97.9% | 1 | 374 | 0.3% |
| AWAvenue Ads Rule | 909 | 755 | 83.1% | 0 | 755 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,850,846** | 🟩 117,660 (5.0%) | 🟩 75,288 (3.7%) | 🟩 26,207 (1.3%) | 🟩 25,358 (1.3%) | 🟩 72,229 (3.8%) | 🟩 20,434 (1.1%) | 🟩 22,492 (1.2%) | 🟩 4,861 (0.3%) | 🟩 99 (0.0%) | 🟩 1,025 (0.1%) | 🟩 16 (0.0%) | 🟩 832 (0.0%) | 🟩 12 (0.0%) | 🟩 49 (0.0%) | · | 🟩 101 (0.0%) | · |
| **2** | 🟩 117,660 (5.0%) | **624,528** | 🟩 1,433 (0.2%) | 🟩 451 (0.1%) | 🟩 410 (0.1%) | 🟩 176 (0.0%) | 🟩 212 (0.0%) | 🟩 134 (0.0%) | 🟩 28 (0.0%) | 🟩 4 (0.0%) | 🟩 3 (0.0%) | · | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **3** | 🟩 75,288 (3.7%) | 🟩 1,433 (0.2%) | **280,732** | 🟨 83,424 (20.9%) | 🟨 81,558 (21.4%) | 🟩 20,316 (5.2%) | 🟩 61,800 (19.4%) | 🟨 58,481 (20.8%) | 🟩 13,051 (4.5%) | 🟩 1,400 (0.5%) | 🟩 1,210 (0.4%) | 🟩 78 (0.0%) | 🟩 379 (0.1%) | 🟩 735 (0.3%) | 🟩 23 (0.0%) | 🟩 374 (0.1%) | 🟩 122 (0.0%) | · |
| **4** | 🟩 26,207 (1.3%) | 🟩 451 (0.1%) | 🟨 83,424 (20.9%) | **201,358** | 🟧 170,028 (79.5%) | 🟩 41 (0.0%) | 🟨 85,767 (39.9%) | 🟨 54,942 (26.8%) | 🟩 33 (0.0%) | 🟩 84 (0.0%) | 🟩 9 (0.0%) | 🟩 35 (0.0%) | 🟩 930 (0.5%) | 🟩 565 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 25,358 (1.3%) | 🟩 410 (0.1%) | 🟨 81,558 (21.4%) | 🟧 170,028 (79.5%) | **182,670** | 🟩 21 (0.0%) | 🟨 76,135 (37.0%) | 🟨 54,380 (29.1%) | 🟩 25 (0.0%) | 🟩 34 (0.0%) | 🟩 2 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 241 (0.1%) | 🟩 2 (0.0%) | 🟩 25 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 72,229 (3.8%) | 🟩 176 (0.0%) | 🟩 20,316 (5.2%) | 🟩 41 (0.0%) | 🟩 21 (0.0%) | **130,959** | 🟩 11 (0.0%) | 🟩 9 (0.0%) | 🟩 19,176 (14.3%) | 🟩 10 (0.0%) | 🟩 11 (0.0%) | · | 🟩 5 (0.0%) | · | · | · | · | · |
| **7** | 🟩 20,434 (1.1%) | 🟩 212 (0.0%) | 🟩 61,800 (19.4%) | 🟨 85,767 (39.9%) | 🟨 76,135 (37.0%) | 🟩 11 (0.0%) | **99,322** | 🟨 41,684 (35.9%) | 🟩 24 (0.0%) | 🟩 30 (0.0%) | 🟩 481 (0.5%) | 🟩 25 (0.0%) | 🟩 10 (0.0%) | 🟩 721 (0.7%) | 🟩 5 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 22,492 (1.2%) | 🟩 134 (0.0%) | 🟨 58,481 (20.8%) | 🟨 54,942 (26.8%) | 🟨 54,380 (29.1%) | 🟩 9 (0.0%) | 🟨 41,684 (35.9%) | **58,622** | 🟩 11 (0.0%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 702 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 4,861 (0.3%) | 🟩 28 (0.0%) | 🟩 13,051 (4.5%) | 🟩 33 (0.0%) | 🟩 25 (0.0%) | 🟩 19,176 (14.3%) | 🟩 24 (0.0%) | 🟩 11 (0.0%) | **22,342** | 🟩 11 (0.0%) | 🟩 13 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 99 (0.0%) | 🟩 4 (0.0%) | 🟩 1,400 (0.5%) | 🟩 84 (0.0%) | 🟩 34 (0.0%) | 🟩 10 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 11 (0.0%) | **16,115** | 🟩 6 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,025 (0.1%) | 🟩 3 (0.0%) | 🟩 1,210 (0.4%) | 🟩 9 (0.0%) | 🟩 2 (0.0%) | 🟩 11 (0.0%) | 🟩 481 (0.5%) | 🟩 5 (0.0%) | 🟩 13 (0.1%) | 🟩 6 (0.0%) | **1,772** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 16 (0.0%) | · | 🟩 78 (0.0%) | 🟩 35 (0.0%) | 🟩 30 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,381** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 832 (0.0%) | 🟩 3 (0.0%) | 🟩 379 (0.1%) | 🟩 930 (0.5%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 10 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **934** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 12 (0.0%) | · | 🟩 735 (0.3%) | 🟩 565 (0.3%) | 🟩 241 (0.1%) | · | 🟩 721 (0.7%) | 🟩 702 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **755** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 49 (0.0%) | 🟩 1 (0.0%) | 🟩 23 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **508** | · | · | · |
| **16** | · | · | 🟩 374 (0.1%) | 🟩 111 (0.1%) | 🟩 25 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **375** | · | · |
| **17** | 🟩 101 (0.0%) | · | 🟩 122 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 54 (0.1%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,850,846 |
| 2 | HaGeZi's Gambling Blocklist | 624,528 |
| 3 | HaGeZi's Ultimate Blocklist | 280,732 |
| 4 | CHN: AdRules DNS List | 201,358 |
| 5 | AdGuard DNS filter | 182,670 |
| 6 | Phishing Army | 130,959 |
| 7 | CHN: anti-AD | 99,322 |
| 8 | OISD Blocklist Small | 58,622 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 22,342 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,115 |
| 11 | Malicious URL Blocklist (URLHaus) | 1,772 |
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
| AdGuard DNS filter | CHN: AdRules DNS List | 170,028 | 🟧 79.5% | 93.1% | 84.4% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 117,660 | 🟩 5.0% | 6.4% | 18.8% |
| CHN: anti-AD | CHN: AdRules DNS List | 85,767 | 🟨 39.9% | 86.4% | 42.6% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 83,424 | 🟨 20.9% | 41.4% | 29.7% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 81,558 | 🟨 21.4% | 44.6% | 29.1% |
| AdGuard DNS filter | CHN: anti-AD | 76,135 | 🟨 37.0% | 41.7% | 76.7% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 75,288 | 🟩 3.7% | 4.1% | 26.8% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,229 | 🟩 3.8% | 55.2% | 3.9% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 61,800 | 🟩 19.4% | 62.2% | 22.0% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 58,481 | 🟨 20.8% | 20.8% | 99.8% |
| CHN: AdRules DNS List | OISD Blocklist Small | 54,942 | 🟨 26.8% | 27.3% | 93.7% |
| AdGuard DNS filter | OISD Blocklist Small | 54,380 | 🟨 29.1% | 29.8% | 92.8% |
| CHN: anti-AD | OISD Blocklist Small | 41,684 | 🟨 35.9% | 42.0% | 71.1% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 26,207 | 🟩 1.3% | 13.0% | 1.4% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 25,358 | 🟩 1.3% | 13.9% | 1.4% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 22,492 | 🟩 1.2% | 1.2% | 38.4% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 20,434 | 🟩 1.1% | 20.6% | 1.1% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 20,316 | 🟩 5.2% | 15.5% | 7.2% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 19,176 | 🟩 14.3% | 14.6% | 85.8% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Ultimate Blocklist | 13,051 | 🟩 4.5% | 58.4% | 4.6% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,852,751 | 1,850,846 | 0.1% |
| HaGeZi's Gambling Blocklist | 624,564 | 624,528 | 0.0% |
| HaGeZi's Ultimate Blocklist | 282,345 | 280,732 | 0.6% |
| CHN: AdRules DNS List | 205,333 | 201,358 | 1.9% |
| AdGuard DNS filter | 185,104 | 182,670 | 1.3% |
| Phishing Army | 152,865 | 130,959 | 14.3% |
| CHN: anti-AD | 100,054 | 99,322 | 0.7% |
| OISD Blocklist Small | 60,181 | 58,622 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 24,081 | 22,342 | 7.2% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,378 | 16,115 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 1,862 | 1,772 | 4.8% |
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
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: AdRules DNS List, CHN: anti-AD, HaGeZi's Ultimate Blocklist | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |

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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,752,252 |
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
| pages.dev | 3,482 |
| cloudfront.net | 3,041 |
| vercel.app | 2,615 |
| weebly.com | 2,396 |
| wixstudio.com | 2,356 |
| web.app | 2,339 |
| firebaseapp.com | 2,020 |
| eu.cc | 1,812 |
| hl.cn | 1,717 |
| r2.dev | 1,483 |
| amazonaws.com | 1,407 |
| run.app | 1,096 |
| blogspot.com | 1,084 |
| allserial.icu | 639 |
| co.com | 607 |
| duckdns.org | 594 |
| netlify.app | 587 |
| googleapis.com | 549 |
| lovable.app | 537 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 54.2s |
| 源成功率 | 18/18 |
| 缓存命中 | 6 |
| 精确去重 | 718,183 |
| 规范化去重 | 3,737 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 37 |
| 模式丢弃 | 1,037 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.1 字符 |
| 最短/最长域名 | 2 / 186 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-10-31*
