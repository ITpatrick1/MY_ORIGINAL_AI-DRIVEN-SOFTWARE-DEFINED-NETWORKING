# Data Mining Report — Tumba College SDN
Generated: 2026-05-15 13:24:49

## Performance KPIs
| KPI | Value | Target | Pass |
|-----|-------|--------|------|
| ML Reaction to Congestion | 50.9 ms | 100 ms | ✅ |
| Staff LAN Throughput vs Legacy Baseline | 582.9 % | 20 % | ✅ |
| Detected vs Blocked Malicious Flows | 100.0 % | 90 % | ✅ |
| Staff LAN Latency SLO | 4.0 ms latency | 10 ms latency | ✅ |

## Gap Analysis Summary
Intelligent SDN improves 8/8 metrics. Key wins: automated failover (<1s vs manual), DDoS detection (<0.5s), 89% reduction in manual ICT hours, 50% increase in Staff LAN throughput.

## Traffic Profile Matrix
| Zone | VLAN | Priority | Bandwidth Target | Performance Target |
|------|------|----------|------------------|--------------------|
| Staff LAN | 10 | 1 | 40 Mbps guaranteed | <10ms latency, 99.9% uptime 08:00-17:00 |
| Server Zone | 20 | 1 | 50 Mbps guaranteed, burstable to 100 | <10ms latency, 99.95% uptime |
| IT Lab | 30 | 2 | 30 Mbps during class, 10 Mbps off-peak | <20ms latency during lab sessions |
| Student Wi-Fi | 40 | 3 | 20 Mbps shared, throttled during congestion | <50ms latency, best-effort |
