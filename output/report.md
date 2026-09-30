# AdGuard Rules Merger V6 — 规则分析报告

> 生成时间：2026-09-30 05:13:59 | 源：18/18 | 缓存命中：8

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 3,341,650 |
| Allow 白名单 | 62 |
| 综合去重率 | 15.8% |
| 聚合精简 | 40,140 |
| 冲突消解 | 8 |
| 带 $ 修饰符规则 | 5 |
| 总耗时 | 59.6s |

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,968,890 | - |
| 去重后（精确 582,877 / 规范化 4,147 / 正则 0） | 3,381,866 | -587,024 |
| 聚合后（精确 40,138 / 通配符 2 / 升级 0） | 3,341,726 | -40,140 |
| 冲突消解后 | 3,341,712 | -8 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| domain | 3,341,576 |
| ip | 72 |
| regex | 63 |
| wildcard | 1 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| malware | 2,371,616 |
| other | 578,445 |
| ads | 329,941 |
| phishing | 61,106 |
| tracking | 376 |
| mining | 166 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 2,371,631 | 2,370,033 | 99.9% | 2,220,604 | 149,429 | 93.7% |
| HaGeZi's Gambling Blocklist | 568,556 | 568,532 | 100.0% | 562,682 | 5,850 | 99.0% |
| HaGeZi's Ultimate Blocklist | 286,439 | 284,954 | 99.5% | 123,396 | 161,558 | 43.3% |
| Phishing Army | 149,787 | 126,493 | 84.4% | 32,934 | 93,559 | 26.0% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 40,195 | 36,106 | 89.8% | 14,649 | 21,457 | 40.6% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,325 | 16,065 | 98.4% | 14,497 | 1,568 | 90.2% |
| CHN: AdRules DNS List | 195,867 | 191,987 | 98.0% | 11,076 | 180,911 | 5.8% |
| CHN: anti-AD | 98,759 | 98,036 | 99.3% | 7,535 | 90,501 | 7.7% |
| AdGuard DNS filter | 176,037 | 173,694 | 98.7% | 4,927 | 168,767 | 2.8% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 100.0% | 1,266 | 110 | 92.0% |
| Malicious URL Blocklist (URLHaus) | 3,352 | 2,654 | 79.2% | 1,030 | 1,624 | 38.8% |
| Stalkerware Indicators List | 925 | 506 | 54.7% | 444 | 62 | 87.7% |
| OISD Blocklist Small | 57,079 | 55,599 | 97.4% | 82 | 55,517 | 0.1% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 100.0% | 16 | 0 | 100.0% |
| Scam Blocklist by DurableNapkin | 952 | 949 | 99.7% | 4 | 945 | 0.4% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 384 | 376 | 97.9% | 1 | 375 | 0.3% |
| AWAvenue Ads Rule | 898 | 743 | 82.7% | 0 | 743 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **2,370,033** | 🟩 4,604 (0.2%) | 🟩 71,917 (2.8%) | 🟩 10,053 (0.4%) | 🟩 8,732 (0.3%) | 🟩 80,276 (3.3%) | 🟩 6,105 (0.2%) | 🟩 6,620 (0.3%) | 🟩 8,072 (0.3%) | 🟩 124 (0.0%) | 🟩 1,546 (0.1%) | 🟩 12 (0.0%) | 🟩 833 (0.0%) | 🟩 7 (0.0%) | 🟩 43 (0.0%) | · | 🟩 102 (0.0%) | · |
| **2** | 🟩 4,604 (0.2%) | **568,532** | 🟩 1,735 (0.2%) | 🟩 436 (0.1%) | 🟩 394 (0.1%) | 🟩 178 (0.0%) | 🟩 210 (0.0%) | 🟩 132 (0.0%) | 🟩 15 (0.0%) | 🟩 1 (0.0%) | 🟩 23 (0.0%) | · | 🟩 2 (0.0%) | · | · | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 71,917 (2.8%) | 🟩 1,735 (0.2%) | **284,954** | 🟨 84,395 (21.5%) | 🟨 82,590 (22.0%) | 🟩 11,997 (3.0%) | 🟩 59,152 (18.3%) | 🟩 55,272 (19.4%) | 🟩 1,427 (0.4%) | 🟩 1,525 (0.5%) | 🟩 206 (0.1%) | 🟩 97 (0.0%) | 🟩 387 (0.1%) | 🟩 724 (0.3%) | 🟩 30 (0.0%) | 🟩 375 (0.1%) | 🟩 100 (0.0%) | · |
| **4** | 🟩 10,053 (0.4%) | 🟩 436 (0.1%) | 🟨 84,395 (21.5%) | **191,987** | 🟧 161,059 (78.7%) | 🟩 26 (0.0%) | 🟨 84,474 (41.1%) | 🟨 52,039 (26.6%) | 🟩 32 (0.0%) | 🟩 81 (0.0%) | 🟩 9 (0.0%) | 🟩 34 (0.0%) | 🟩 945 (0.5%) | 🟩 564 (0.3%) | 🟩 3 (0.0%) | 🟩 109 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 8,732 (0.3%) | 🟩 394 (0.1%) | 🟨 82,590 (22.0%) | 🟧 161,059 (78.7%) | **173,694** | 🟩 17 (0.0%) | 🟨 75,194 (38.3%) | 🟨 51,442 (28.9%) | 🟩 23 (0.0%) | 🟩 31 (0.0%) | 🟩 1 (0.0%) | 🟩 29 (0.0%) | 🟩 21 (0.0%) | 🟩 240 (0.1%) | 🟩 2 (0.0%) | 🟩 23 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 80,276 (3.3%) | 🟩 178 (0.0%) | 🟩 11,997 (3.0%) | 🟩 26 (0.0%) | 🟩 17 (0.0%) | **126,493** | 🟩 12 (0.0%) | 🟩 6 (0.0%) | 🟩 20,504 (14.4%) | 🟩 10 (0.0%) | 🟩 16 (0.0%) | · | 🟩 3 (0.0%) | · | · | · | 🟩 1 (0.0%) | · |
| **7** | 🟩 6,105 (0.2%) | 🟩 210 (0.0%) | 🟩 59,152 (18.3%) | 🟨 84,474 (41.1%) | 🟨 75,194 (38.3%) | 🟩 12 (0.0%) | **98,036** | 🟨 39,896 (35.1%) | 🟩 25 (0.0%) | 🟩 30 (0.0%) | 🟩 419 (0.4%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 711 (0.7%) | 🟩 5 (0.0%) | 🟩 62 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 6,620 (0.3%) | 🟩 132 (0.0%) | 🟩 55,272 (19.4%) | 🟨 52,039 (26.6%) | 🟨 51,442 (28.9%) | 🟩 6 (0.0%) | 🟨 39,896 (35.1%) | **55,599** | 🟩 11 (0.0%) | 🟩 21 (0.0%) | 🟩 5 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 689 (1.2%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 54 (0.1%) | · |
| **9** | 🟩 8,072 (0.3%) | 🟩 15 (0.0%) | 🟩 1,427 (0.4%) | 🟩 32 (0.0%) | 🟩 23 (0.0%) | 🟩 20,504 (14.4%) | 🟩 25 (0.0%) | 🟩 11 (0.0%) | **36,106** | 🟩 11 (0.0%) | 🟩 31 (0.1%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 3 (0.0%) | · |
| **10** | 🟩 124 (0.0%) | 🟩 1 (0.0%) | 🟩 1,525 (0.5%) | 🟩 81 (0.0%) | 🟩 31 (0.0%) | 🟩 10 (0.0%) | 🟩 30 (0.0%) | 🟩 21 (0.0%) | 🟩 11 (0.0%) | **16,065** | 🟩 5 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,546 (0.1%) | 🟩 23 (0.0%) | 🟩 206 (0.1%) | 🟩 9 (0.0%) | 🟩 1 (0.0%) | 🟩 16 (0.0%) | 🟩 419 (0.4%) | 🟩 5 (0.0%) | 🟩 31 (0.1%) | 🟩 5 (0.0%) | **2,654** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 12 (0.0%) | · | 🟩 97 (0.0%) | 🟩 34 (0.0%) | 🟩 29 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,376** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 833 (0.0%) | 🟩 2 (0.0%) | 🟩 387 (0.1%) | 🟩 945 (0.5%) | 🟩 21 (0.0%) | 🟩 3 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **949** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 7 (0.0%) | · | 🟩 724 (0.3%) | 🟩 564 (0.3%) | 🟩 240 (0.1%) | · | 🟩 711 (0.7%) | 🟩 689 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **743** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 43 (0.0%) | · | 🟩 30 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **506** | · | · | · |
| **16** | · | · | 🟩 375 (0.1%) | 🟩 109 (0.1%) | 🟩 23 (0.0%) | · | 🟩 62 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **376** | · | · |
| **17** | 🟩 102 (0.0%) | 🟩 1 (0.0%) | 🟩 100 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | 🟩 1 (0.0%) | 🟩 258 (0.3%) | 🟩 54 (0.1%) | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **16** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 2,370,033 |
| 2 | HaGeZi's Gambling Blocklist | 568,532 |
| 3 | HaGeZi's Ultimate Blocklist | 284,954 |
| 4 | CHN: AdRules DNS List | 191,987 |
| 5 | AdGuard DNS filter | 173,694 |
| 6 | Phishing Army | 126,493 |
| 7 | CHN: anti-AD | 98,036 |
| 8 | OISD Blocklist Small | 55,599 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 36,106 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,065 |
| 11 | Malicious URL Blocklist (URLHaus) | 2,654 |
| 12 | ShadowWhisperer's Dating List | 1,376 |
| 13 | Scam Blocklist by DurableNapkin | 949 |
| 14 | AWAvenue Ads Rule | 743 |
| 15 | Stalkerware Indicators List | 506 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 376 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 16 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 161,059 | 🟧 78.7% | 92.7% | 83.9% |
| CHN: anti-AD | CHN: AdRules DNS List | 84,474 | 🟨 41.1% | 86.2% | 44.0% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 84,395 | 🟨 21.5% | 44.0% | 29.6% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 82,590 | 🟨 22.0% | 47.5% | 29.0% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 80,276 | 🟩 3.3% | 63.5% | 3.4% |
| AdGuard DNS filter | CHN: anti-AD | 75,194 | 🟨 38.3% | 43.3% | 76.7% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 71,917 | 🟩 2.8% | 3.0% | 25.2% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 59,152 | 🟩 18.3% | 60.3% | 20.8% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 55,272 | 🟩 19.4% | 19.4% | 99.4% |
| CHN: AdRules DNS List | OISD Blocklist Small | 52,039 | 🟨 26.6% | 27.1% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 51,442 | 🟨 28.9% | 29.6% | 92.5% |
| CHN: anti-AD | OISD Blocklist Small | 39,896 | 🟨 35.1% | 40.7% | 71.8% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 20,504 | 🟩 14.4% | 16.2% | 56.8% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 11,997 | 🟩 3.0% | 9.5% | 4.2% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 10,053 | 🟩 0.4% | 5.2% | 0.4% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 8,732 | 🟩 0.3% | 5.0% | 0.4% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 8,072 | 🟩 0.3% | 22.4% | 0.3% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 6,620 | 🟩 0.3% | 0.3% | 11.9% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 6,105 | 🟩 0.2% | 6.2% | 0.3% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 4,604 | 🟩 0.2% | 0.2% | 0.8% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 2,371,631 | 2,370,033 | 0.1% |
| HaGeZi's Gambling Blocklist | 568,556 | 568,532 | 0.0% |
| HaGeZi's Ultimate Blocklist | 286,439 | 284,954 | 0.5% |
| CHN: AdRules DNS List | 195,867 | 191,987 | 2.0% |
| AdGuard DNS filter | 176,037 | 173,694 | 1.3% |
| Phishing Army | 149,787 | 126,493 | 15.6% |
| CHN: anti-AD | 98,759 | 98,036 | 0.7% |
| OISD Blocklist Small | 57,079 | 55,599 | 2.6% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 40,195 | 36,106 | 10.2% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,325 | 16,065 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 3,352 | 2,654 | 20.8% |
| ShadowWhisperer's Dating List | 1,376 | 1,376 | 0.0% |
| Scam Blocklist by DurableNapkin | 952 | 949 | 0.3% |
| AWAvenue Ads Rule | 898 | 743 | 17.3% |
| Stalkerware Indicators List | 925 | 506 | 45.3% |
| HaGeZi's Windows/Office Tracker Blocklist | 384 | 376 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 16 | 16 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 被白名单移除的拦截规则；展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `autocomplete.clearbit.com` | `||autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@||autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `stats.tj.gov.cn` | `||stats.tj.gov.cn^` | HaGeZi's Ultimate Blocklist | `@@||tj.gov.cn^` | CHN: anti-AD | 级联 |
| `settings-win.data.microsoft.com` | `||settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@||settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `||global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@||api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `||ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@||ads.privacy.qq.com^` | CHN: anti-AD | 精确 |
| `ad.10010.com` | `||ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, HaGeZi's Ultimate Blocklist, CHN: anti-AD, CHN: AdRules DNS List | `@@||ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `||ad.ourgame.com^` | CHN: AdRules DNS List | `@@||ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `app.adjust.com` | `||app.adjust.com^` | AdGuard DNS filter | `@@||app.adjust.com^` | CHN: anti-AD | 精确 |

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
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 0.00 | 解析到私有/回环 IP: ['172.26.255.11', '172.26.255.1', '172.26.255.2', '172.26.255.12'] | CHN: anti-AD |
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
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 3,341,576 |
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
| weebly.com | 4,638 |
| cloudfront.net | 3,475 |
| hl.cn | 2,989 |
| wixstudio.com | 2,257 |
| web.app | 2,057 |
| amazonaws.com | 2,038 |
| firebaseapp.com | 1,994 |
| eu.cc | 1,966 |
| pages.dev | 1,847 |
| r2.dev | 1,773 |
| run.app | 1,238 |
| sa.com | 1,198 |
| ru.com | 1,090 |
| vercel.app | 1,003 |
| my.id | 1,000 |
| framer.app | 943 |
| appspot.com | 847 |
| biz.id | 806 |
| aliyuncs.com | 715 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 59.6s |
| 源成功率 | 18/18 |
| 缓存命中 | 8 |
| 精确去重 | 582,877 |
| 规范化去重 | 4,147 |
| 正则去重 | 0 |
| 质量过滤丢弃 | 38 |
| 模式丢弃 | 1,047 |
| CSS 丢弃 | 0 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 16.8 字符 |
| 最短/最长域名 | 2 / 130 字符 |

---
*AdGuard Rules Merger V6 · 自动生成 · 2026-09-30*
