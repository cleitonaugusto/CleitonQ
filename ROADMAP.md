# CleitonQ — Roadmap

*Cleiton Augusto Correa Bezerra*

Plano técnico do projeto, por fase.

---

## Fase 1 — Fundação (v0.1) `[ATUAL]`

**Objetivo:** crate publicável, API estável, testes completos.

### Tarefas

- [x] `src/kem.rs` — ML-KEM-1024 session establishment
- [x] `src/dsa.rs` — ML-DSA-87 command signing / verification
- [x] `src/channel.rs` — AuthChannel com domain separation
- [x] `src/lib.rs` — API pública + prelude
- [x] `examples/basic_session.rs` — demonstração completa
- [x] `examples/mavlink_c2.rs` — integração MAVLink
- [x] `benches/pqc_bench.rs` — benchmarks Criterion
- [x] `README.md` — documentação
- [x] `cargo test --workspace` — todos passando (21/21)
- [x] `cargo bench` — coletar números reais
- [x] Publicar no `crates.io` — v0.1.0 publicado em 2026-06-16
- [ ] Publicar documentação no `docs.rs`

**Entrega:** `v0.1.0` no crates.io

---

## Fase 2 — Validação (v0.2) `[Q2–Q3 2026]`

**Objetivo:** benchmarks em hardware ARM real, integração MAVLink testada,
abrir diálogo técnico com a comunidade MAVLink sobre PQC.

### Tarefas técnicas

- [ ] Benchmarks no Raspberry Pi 5 (ARM Cortex-A76) — pendente, sem hardware
  ARM disponível no momento. Issue do MAVLink segue sem esses números;
  adicionar quando houver acesso a um dispositivo real.
  - Latência ML-KEM e ML-DSA em hardware embarcado real
  - Comparação com ECDSA/X25519 atual do MAVLink
- [x] Integração real com MAVLink v2 (`examples/mavlink_c2.rs`, usando o crate
  oficial `mavlink` / github.com/mavlink/rust-mavlink)
  - [x] Wrapper para `COMMAND_LONG`, `SET_POSITION_TARGET_LOCAL_NED` — frames
    reais (header + payload + CRC), não mais struct simulada
  - [x] Teste com socket UDP real (`examples/mavlink_udp_link.rs`) —
    achou e corrigiu um bug real de buffer (ver `SECURITY.md`)
  - [x] Teste com MAVProxy como relay — **achado importante**: o formato
    atual (assinatura anexada após o frame) não sobrevive a um relay
    MAVLink-aware (MAVProxy, mavlink-router, QGroundControl como proxy).
    Só funciona em link direto ponto-a-ponto. Detalhe completo em
    `SECURITY.md`. Isso precisa ser resolvido antes do RFC da Fase 3.
- [x] `nonce.rs` — `AtomicNonce` (geração) e `NonceTracker` (anti-replay)
  thread-safe para loops de controle concorrentes
- [ ] Suporte a `no_std` (base para microcontroladores)
- [x] Fuzzing dos verificadores de pacotes (cargo-fuzz, `fuzz/fuzz_targets/`)
  — sem crashes em milhões de execuções até o momento
- [x] Testes de MITM ativo (`tests/mitm_active.rs`): substituição de
  ciphertext entre sessões, replay cross-session, splicing de assinatura
- [x] Testes de exaustão de recursos (`tests/dos_stress.rs`): pacotes
  malformados em volume, pacotes de até 16MiB, flood de pacotes forjados
- [x] `rotation.rs` — rotação e revogação de chave ML-DSA-87
  (`KeyRegistry`/`RotatingSigningKey`), sem mudar o formato de wire do
  `dsa.rs` existente
- [x] `SECURITY.md` — gaps conhecidos documentados honestamente

### Comunidade

- [x] Issue em `github.com/mavlink/mavlink` — aberta em 2026-06-16:
  https://github.com/mavlink/mavlink/issues/2525 — pergunta técnica sobre
  o roadmap de PQC do projeto, com a implementação de referência e os
  números medidos como evidência. Aguardando resposta dos maintainers.
- [x] Paper técnico: threat model, protocol design, implementation,
  evaluation, security analysis. Publicado em Zenodo 2026-06-20 —
  https://doi.org/10.5281/zenodo.20776349
- [ ] Post em `discuss.ardupilot.org` com link para o paper e a discussão.

**Entrega:** `v0.2.0`

---

## Fase 3 — Padronização (v0.3) `[Q4 2026]`

**Objetivo:** suporte a confidencialidade, `no_std`, STM32.

### Tarefas técnicas

- [ ] Confidencialidade: AES-256-GCM sobre o canal autenticado
- [ ] Suporte `no_std + alloc` (STM32F4, Pixhawk hardware)
- [ ] Integração com `embassy` (async embedded Rust)
- [ ] `CleitonQSession` — objeto de sessão com estado encapsulado
- [ ] CLI `cleitonq-keygen` — ferramenta de geração e auditoria de chaves

### Padronização

- [x] **MAVLink RFC formal:** proposta de extensão do protocolo MAVLink
  para PQC, submetida ao grupo de trabalho MAVLink no GitHub —
  Issue #2527 e PR #2528 abertos em 2026-06-16.
- [ ] Submissão para conferência: USENIX WOOT, IEEE S&P Workshop, ou
  ICRA Workshop on Security.
- [ ] Contato técnico com ArduPilot core team, PX4 Autopilot security
  track, UAVCAN/DroneCAN working group.

**Entrega:** `v0.3.0` + RFC MAVLink

---

## Fase 4 — Maturidade (v1.0) `[2027]`

**Objetivo:** produção-pronto, certificado, auditado.

### Tarefas técnicas

- [ ] Auditoria de segurança por terceiros (Trail of Bits, NCC Group, ou equivalente)
- [ ] Certificação FIPS 140-3 (módulo criptográfico)
- [ ] Suporte a HSM (Nitrokey, YubiHSM) para proteção da signing key
- [x] SDK Python (`pip install cleitonq`) via PyO3 — `cleitonq-python/`
- [x] SDK C FFI (`libcleitonq_capi.a` / `.so`) para integração com sistemas legados

**Entrega:** `v1.0.0`

---

## Fase 5 — Outros protocolos `[condicional, após Fase 1-4]`

A biblioteca `cleitonq` (`kem.rs`, `dsa.rs`, `channel.rs`) é agnóstica de
protocolo — MAVLink foi o primeiro alvo por contexto (projeto Laminar).
O mesmo gap de PQC existe em outros protocolos binários usados em sistemas
com link não confiável e custo alto de breach:

| Vertical | Protocolo |
|---|---|
| Robótica | ROS2/DDS |
| Veicular/automotivo | CAN bus, UAVCAN |
| Industrial/SCADA | Modbus, OPC-UA |
| IoT | MQTT, CoAP |

---

## Visão de longo prazo

```
2026 Q2  Paper publicado (preprint Zenodo/TechRxiv)
2026 Q2  Diálogo técnico iniciado — MAVLink issue #2525
2026 Q2  Python SDK (PyO3) e C FFI concluídos
2026 Q3  RFC MAVLink formal
2026 Q4  Adoção avaliada por ArduPilot ou PX4
2027 Q2  v1.0 auditado
```

— Cleiton Augusto Correa Bezerra
