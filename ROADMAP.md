# CleitonQ — Roadmap

*Cleiton Augusto Correa Bezerra*

---

## Status atual — v0.2.0 (2026-Q2)

### Entregues

- [x] ML-KEM-1024 + ML-DSA-87 + HMAC-SHA3-256 (NIST FIPS 203/204/202)
- [x] Hybrid X25519 + ML-KEM-1024 (transição clássico → PQC)
- [x] HSM backends: PKCS#11 (SoftHSM2, YubiHSM2) + TPM2 (Jetson Orin, RPi5)
- [x] AuthChannel com domain separation e anti-replay por nonce atômico
- [x] ML-DSA-87 signing com rotação e revogação de chaves (`rotation.rs`)
- [x] **C API com CMake** — `capi/` — `find_package(CleitonQ)` em 10 minutos
- [x] **ROS2 package** — `ros2-cleitonq/` — colcon build, parallel-topic pattern
- [x] Python SDK via PyO3 — `cleitonq-python/`
- [x] Benchmarks em Cortex-A76 (Jetson Orin target) — CI self-hosted
- [x] Fuzzing (`cargo fuzz`) — sem crashes em milhões de execuções
- [x] Testes MITM ativo, replay cross-session, flood de pacotes malformados
- [x] Paper técnico publicado — [Zenodo DOI 10.5281/zenodo.20776349](https://doi.org/10.5281/zenodo.20776349)
- [x] **IETF Internet-Draft publicado** — [draft-bezerra-relay-auth-transparency](https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/)
- [x] **GHSA-f5rj-mrxh-r7vm** — advisory publicado, CVE em atribuição
- [x] Key ceremony completa: geração, distribuição, revogação documentadas

---

## Fase 3 — Produto e Padronização `[2026 Q3–Q4]`

### Técnico

- [ ] `no_std + alloc` — desbloqueia CAN/DroneCAN/AUTOSAR SecOC e STM32/Pixhawk
- [ ] Integração `embassy` (async embedded Rust)
- [ ] CLI `cleitonq-keygen` — geração e auditoria de chaves em campo
- [ ] `cleitonq-fleet` v0.1 — servidor de key management para frotas autônomas

### Padronização

- [x] MAVLink RFC #2527 submetido (2026-Q2)
  — WG indicou preferência pelo mecanismo INCOMPAT_FLAGS existente.
  Análise técnica mostra que INCOMPAT_FLAGS causa perda total de frames
  em relays sem suporte, ao contrário da abordagem MSG_ID proposta.
  Documentado em [draft-bezerra-relay-auth-transparency §4](https://datatracker.ietf.org/doc/draft-bezerra-relay-auth-transparency/).
  **Caminho de padronização: IETF.**
- [ ] **IACR ePrint** — submissão após CVE atribuído
- [ ] **OMG DDS-Security PQC extension** — proposta formal (draft em `docs/omg/`)
- [ ] **IEEE S&P 2027** — deadline ~Out 2026
- [ ] Notificação coordenada: MAVProxy, QGroundControl, ArduPilot, PX4 (após CVE)

---

## Fase 4 — Maturidade `[2027]`

- [ ] Auditoria externa (Trail of Bits ou NCC Group)
- [ ] FIPS 140-3 validation (processo formal)
- [ ] Suporte a Iridium SBD e links satélite de baixa banda
- [ ] Verticais adicionais: CAN/AUTOSAR SecOC, OPC-UA, CCSDS

---

## Visão de longo prazo

```
2026 Q2  Paper — Zenodo DOI 10.5281/zenodo.20776349                [✓]
2026 Q2  IETF Internet-Draft publicado                             [✓]
2026 Q2  GHSA-f5rj-mrxh-r7vm — CVE pending                        [✓]
2026 Q2  MAVLink RFC submetido — padronização via IETF             [✓]
2026 Q2  C API + CMake (find_package) + ROS2 package colcon        [✓]
2026 Q3  CVE atribuído → IACR ePrint + notificação maintainers
2026 Q3  no_std → CAN/DroneCAN/STM32
2026 Q3  cleitonq-fleet v0.1 (key management para frotas)
2026 Q4  OMG DDS-Security PQC extension submetida
2026 Q4  IEEE S&P 2027 submetido
2027 Q1  Auditoria externa
2027 Q2  v1.0 — auditado, FIPS 140-3 em processo
2027+    CAN/AUTOSAR, OPC-UA/SCADA, CCSDS/satélites
```

---

## Mapa de protocolos

| Vertical | Protocolo | Status |
|---|---|---|
| Drones/UAS | MAVLink v2 | RFC submetida; fix disponível — `CLEITONQ_CHUNK` |
| Robótica autônoma | ROS2/DDS | Package disponível — parallel-topic pattern |
| Embedded/avionics | CAN/DroneCAN | Aguarda `no_std` (Fase 3) |
| Industrial | OPC-UA, IEC 62443 | Planejado |
| Satélites | CCSDS | Longo prazo |

---

— Cleiton Augusto Correa Bezerra
