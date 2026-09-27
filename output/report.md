# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-09-27 14:36:28 | 源：18/18 | 缓存命中：18

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 3,294,818 |
| Allow 白名单 | 62 |
| 综合去重率 | 16.2% |
| 聚合精简 | 40,013 |
| 冲突消解 | 8 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 39.1s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,932,726 | - |
| 去重后（精确 597,819 / 规范化 0 / 正则 0） | 3,334,907 | -597,819 |
| 聚合后（精确 40,011 / 通配符 2 / 升级 0） | 3,294,894 | -40,013 |
| 冲突消解后 | 3,294,880 | -8 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 3,294,744 |
| ip | 72 |
| regex | 63 |
| wildcard | 1 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,328,487 |
| other | 570,769 |
| ads | 334,018 |
| phishing | 60,999 |
| tracking | 378 |
| mining | 167 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,328,533 | 2,326,894 | 99.9% | 2,175,806 | 151,088 | 93.5% |
| HaGeZi's Gambling Blocklist | 561,778 | 561,754 | 100.0% | 555,104 | 6,650 | 98.8% |
| HaGeZi's Ultimate Blocklist | 285,253 | 283,769 | 99.5% | 121,297 | 162,472 | 42.7% |
| Phishing Army | 149,330 | 126,271 | 84.6% | 32,934 | 93,337 | 26.1% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 39,947 | 35,990 | 90.1% | 14,665 | 21,325 | 40.7% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,228 | 15,968 | 98.4% | 14,399 | 1,569 | 90.2% |
| CHN: AdRules DNS List | 202,508 | 198,629 | 98.1% | 11,033 | 187,596 | 5.6% |
| CHN: anti-AD | 101,488 | 100,766 | 99.3% | 7,529 | 93,237 | 7.5% |
| AdGuard DNS filter | 182,787 | 180,446 | 98.7% | 4,964 | 175,482 | 2.8% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 100.0% | 1,266 | 110 | 92.0% |
| Malicious URL Blocklist (URLHaus) | 3,425 | 2,706 | 79.0% | 1,041 | 1,665 | 38.5% |
| Stalkerware Indicators List | 925 | 506 | 54.7% | 443 | 63 | 87.5% |
| OISD Blocklist Small | 56,603 | 55,123 | 97.4% | 82 | 55,041 | 0.1% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 100.0% | 16 | 0 | 100.0% |
| Scam Blocklist by DurableNapkin | 933 | 930 | 99.7% | 4 | 926 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 386 | 378 | 97.9% | 1 | 377 | 0.3% |
| AWAvenue Ads Rule | 898 | 743 | 82.7% | 0 | 743 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **2,326,894** | 🟩 5,415 (0.2%) | 🟩 72,658 (2.9%) | 🟩 10,477 (0.4%) | 🟩 9,179 (0.4%) | 🟩 80,161 (3.4%) | 🟩 6,545 (0.3%) | 🟩 6,847 (0.3%) | 🟩 8,044 (0.3%) | 🟩 124 (0.0%) | 🟩 1,587 (0.1%) | 🟩 12 (0.0%) | 🟩 833 (0.0%) | 🟩 7 (0.0%) | 🟩 44 (0.0%) | · | 🟩 101 (0.0%) | · |
| **2** | 🟩 5,415 (0.2%) | **561,754** | 🟩 1,676 (0.2%) | 🟩 437 (0.1%) | 🟩 395 (0.1%) | 🟩 179 (0.0%) | 🟩 211 (0.0%) | 🟩 132 (0.0%) | 🟩 13 (0.0%) | 🟩 1 (0.0%) | 🟩 31 (0.0%) | · | 🟩 2 (0.0%) | · | · | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 72,658 (2.9%) | 🟩 1,676 (0.2%) | **283,769** | 🟨 85,088 (21.4%) | 🟨 83,288 (21.9%) | 🟩 11,851 (3.0%) | 🟩 59,879 (18.4%) | 🟩 54,886 (19.3%) | 🟩 1,434 (0.5%) | 🟩 1,526 (0.5%) | 🟩 208 (0.1%) | 🟩 97 (0.0%) | 🟩 389 (0.1%) | 🟩 724 (0.3%) | 🟩 30 (0.0%) | 🟩 377 (0.1%) | 🟩 100 (0.0%) | · |
| **4** | 🟩 10,477 (0.4%) | 🟩 437 (0.1%) | 🟨 85,088 (21.4%) | **198,629** | 🟧 167,775 (79.4%) | 🟩 26 (0.0%) | 🟨 87,194 (41.1%) | 🟨 51,603 (25.5%) | 🟩 33 (0.0%) | 🟩 81 (0.0%) | 🟩 8 (0.0%) | 🟩 34 (0.0%) | 🟩 926 (0.5%) | 🟩 564 (0.3%) | 🟩 3 (0.0%) | 🟩 109 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 9,179 (0.4%) | 🟩 395 (0.1%) | 🟨 83,288 (21.9%) | 🟧 167,775 (79.4%) | **180,446** | 🟩 17 (0.0%) | 🟨 77,917 (38.3%) | 🟨 51,000 (27.6%) | 🟩 25 (0.0%) | 🟩 31 (0.0%) | 🟩 2 (0.0%) | 🟩 29 (0.0%) | 🟩 21 (0.0%) | 🟩 240 (0.1%) | 🟩 2 (0.0%) | 🟩 23 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 80,161 (3.4%) | 🟩 179 (0.0%) | 🟩 11,851 (3.0%) | 🟩 26 (0.0%) | 🟩 17 (0.0%) | **126,271** | 🟩 11 (0.0%) | 🟩 6 (0.0%) | 🟩 20,364 (14.4%) | 🟩 9 (0.0%) | 🟩 16 (0.0%) | · | 🟩 3 (0.0%) | · | · | · | 🟩 1 (0.0%) | · |
| **7** | 🟩 6,545 (0.3%) | 🟩 211 (0.0%) | 🟩 59,879 (18.4%) | 🟨 87,194 (41.1%) | 🟨 77,917 (38.3%) | 🟩 11 (0.0%) | **100,766** | 🟨 39,470 (33.9%) | 🟩 26 (0.0%) | 🟩 29 (0.0%) | 🟩 433 (0.4%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 711 (0.7%) | 🟩 5 (0.0%) | 🟩 62 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 6,847 (0.3%) | 🟩 132 (0.0%) | 🟩 54,886 (19.3%) | 🟨 51,603 (25.5%) | 🟨 51,000 (27.6%) | 🟩 6 (0.0%) | 🟨 39,470 (33.9%) | **55,123** | 🟩 12 (0.0%) | 🟩 21 (0.0%) | 🟩 6 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 689 (1.2%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 8,044 (0.3%) | 🟩 13 (0.0%) | 🟩 1,434 (0.5%) | 🟩 33 (0.0%) | 🟩 25 (0.0%) | 🟩 20,364 (14.4%) | 🟩 26 (0.0%) | 🟩 12 (0.0%) | **35,990** | 🟩 11 (0.0%) | 🟩 31 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 3 (0.0%) | · |
| **10** | 🟩 124 (0.0%) | 🟩 1 (0.0%) | 🟩 1,526 (0.5%) | 🟩 81 (0.0%) | 🟩 31 (0.0%) | 🟩 9 (0.0%) | 🟩 29 (0.0%) | 🟩 21 (0.0%) | 🟩 11 (0.0%) | **15,968** | 🟩 5 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,587 (0.1%) | 🟩 31 (0.0%) | 🟩 208 (0.1%) | 🟩 8 (0.0%) | 🟩 2 (0.0%) | 🟩 16 (0.0%) | 🟩 433 (0.4%) | 🟩 6 (0.0%) | 🟩 31 (0.1%) | 🟩 5 (0.0%) | **2,706** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 12 (0.0%) | · | 🟩 97 (0.0%) | 🟩 34 (0.0%) | 🟩 29 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,376** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 833 (0.0%) | 🟩 2 (0.0%) | 🟩 389 (0.1%) | 🟩 926 (0.5%) | 🟩 21 (0.0%) | 🟩 3 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **930** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 7 (0.0%) | · | 🟩 724 (0.3%) | 🟩 564 (0.3%) | 🟩 240 (0.1%) | · | 🟩 711 (0.7%) | 🟩 689 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **743** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 44 (0.0%) | · | 🟩 30 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **506** | · | · | · |
| **16** | · | · | 🟩 377 (0.1%) | 🟩 109 (0.1%) | 🟩 23 (0.0%) | · | 🟩 62 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **378** | · | · |
| **17** | 🟩 101 (0.0%) | 🟩 1 (0.0%) | 🟩 100 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | 🟩 1 (0.0%) | 🟩 258 (0.3%) | 🟩 54 (0.1%) | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **16** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 2,326,894 |
| 2 | HaGeZi's Gambling Blocklist | 561,754 |
| 3 | HaGeZi's Ultimate Blocklist | 283,769 |
| 4 | CHN: AdRules DNS List | 198,629 |
| 5 | AdGuard DNS filter | 180,446 |
| 6 | Phishing Army | 126,271 |
| 7 | CHN: anti-AD | 100,766 |
| 8 | OISD Blocklist Small | 55,123 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 35,990 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 15,968 |
| 11 | Malicious URL Blocklist (URLHaus) | 2,706 |
| 12 | ShadowWhisperer's Dating List | 1,376 |
| 13 | Scam Blocklist by DurableNapkin | 930 |
| 14 | AWAvenue Ads Rule | 743 |
| 15 | Stalkerware Indicators List | 506 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 378 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 16 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 167,775 | 🟧 79.4% | 93.0% | 84.5% |
| CHN: anti-AD | CHN: AdRules DNS List | 87,194 | 🟨 41.1% | 86.5% | 43.9% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 85,088 | 🟨 21.4% | 42.8% | 30.0% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 83,288 | 🟨 21.9% | 46.2% | 29.4% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 80,161 | 🟩 3.4% | 63.5% | 3.4% |
| AdGuard DNS filter | CHN: anti-AD | 77,917 | 🟨 38.3% | 43.2% | 77.3% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 72,658 | 🟩 2.9% | 3.1% | 25.6% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 59,879 | 🟩 18.4% | 59.4% | 21.1% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 54,886 | 🟩 19.3% | 19.3% | 99.6% |
| CHN: AdRules DNS List | OISD Blocklist Small | 51,603 | 🟨 25.5% | 26.0% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 51,000 | 🟨 27.6% | 28.3% | 92.5% |
| CHN: anti-AD | OISD Blocklist Small | 39,470 | 🟨 33.9% | 39.2% | 71.6% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 20,364 | 🟩 14.4% | 16.1% | 56.6% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 11,851 | 🟩 3.0% | 9.4% | 4.2% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 10,477 | 🟩 0.4% | 5.3% | 0.5% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 9,179 | 🟩 0.4% | 5.1% | 0.4% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 8,044 | 🟩 0.3% | 22.4% | 0.3% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 6,847 | 🟩 0.3% | 0.3% | 12.4% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 6,545 | 🟩 0.3% | 6.5% | 0.3% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 5,415 | 🟩 0.2% | 0.2% | 1.0% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,328,533 | 2,326,894 | 0.1% |
| HaGeZi's Gambling Blocklist | 561,778 | 561,754 | 0.0% |
| HaGeZi's Ultimate Blocklist | 285,253 | 283,769 | 0.5% |
| CHN: AdRules DNS List | 202,508 | 198,629 | 1.9% |
| AdGuard DNS filter | 182,787 | 180,446 | 1.3% |
| Phishing Army | 149,330 | 126,271 | 15.4% |
| CHN: anti-AD | 101,488 | 100,766 | 0.7% |
| OISD Blocklist Small | 56,603 | 55,123 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 39,947 | 35,990 | 9.9% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,228 | 15,968 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 3,425 | 2,706 | 21.0% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 0.0% |
| Scam Blocklist by DurableNapkin | 933 | 930 | 0.3% |
| AWAvenue Ads Rule | 898 | 743 | 17.3% |
| Stalkerware Indicators List | 925 | 506 | 45.3% |
| HaGeZi's Windows/Office Tracker Blocklist | 386 | 378 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `ad.10010.com` | `||ad.10010.com^` | CHN: AdRules DNS List, AWAvenue Ads Rule, CHN: anti-AD, HaGeZi's Ultimate Blocklist, OISD Blocklist Small | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `stats.tj.gov.cn` | `||stats.tj.gov.cn^` | HaGeZi's Ultimate Blocklist | `@@||tj.gov.cn^` | CHN: anti-AD | 级联 |
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
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.1', '172.26.255.2', '172.26.255.12', '172.26.255.11'] | CHN: anti-AD |
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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 3,294,744 |
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
| fbcdn.net | 7,037 |
| weebly.com | 4,629 |
| cloudfront.net | 3,473 |
| hl.cn | 3,059 |
| wixstudio.com | 2,256 |
| web.app | 2,057 |
| amazonaws.com | 2,007 |
| firebaseapp.com | 1,993 |
| eu.cc | 1,944 |
| pages.dev | 1,864 |
| r2.dev | 1,773 |
| run.app | 1,226 |
| sa.com | 1,199 |
| ru.com | 1,090 |
| my.id | 1,013 |
| vercel.app | 993 |
| framer.app | 943 |
| appspot.com | 843 |
| biz.id | 804 |
| dynu.org | 782 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 39.1s |
| 源成功率 | 18/18 |
| 缓存命中 | 18 |
| 精确去重 | 597,819 |
| 规范化去重 | 0 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 38 |
| 模式丢弃 | 1,046 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 16.8 字符 |
| 最短/最长域名 | 2 / 130 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-09-27*
