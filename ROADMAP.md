# CleitonQ — Roadmap

*Cleiton Augusto Correa Bezerra*

Este documento é o plano estratégico do projeto. Cada fase tem objetivo técnico,
objetivo de reconhecimento e objetivo financeiro.

---

## Fase 1 — Fundação (v0.1) `[ATUAL]`

**Objetivo técnico:** crate publicável, API estável, testes completos.

**Objetivo de reconhecimento:** existir publicamente com nome e autoria claros.

**Objetivo financeiro:** zero — esta fase é investimento.

### Tarefas

- [x] `src/kem.rs` — ML-KEM-1024 session establishment
- [x] `src/dsa.rs` — ML-DSA-87 command signing / verification
- [x] `src/channel.rs` — AuthChannel com domain separation
- [x] `src/lib.rs` — API pública + prelude
- [x] `examples/basic_session.rs` — demonstração completa
- [x] `examples/mavlink_c2.rs` — integração MAVLink
- [x] `benches/pqc_bench.rs` — benchmarks Criterion
- [x] `README.md` — documento de marketing técnico
- [ ] `cargo test --workspace` — todos passando
- [ ] `cargo bench` — coletar números reais
- [ ] Publicar no `crates.io`
- [ ] Publicar documentação no `docs.rs`

**Entrega:** `v0.1.0` no crates.io

---

## Fase 2 — Autoridade (v0.2) `[Q3 2025]`

**Objetivo técnico:** benchmarks em hardware ARM real, integração MAVLink testada.

**Objetivo de reconhecimento:** paper no IACR ePrint + posts nas comunidades
ArduPilot e PX4. Ser citado.

**Objetivo financeiro:** primeiros contatos com potenciais financiadores.

### Tarefas técnicas

- [ ] Benchmarks no Raspberry Pi 5 (ARM Cortex-A76)
  - Latência ML-KEM e ML-DSA em hardware embarcado real
  - Comparação com ECDSA/X25519 atual do MAVLink
- [ ] Integração real com MAVLink v2
  - Wrapper para `COMMAND_LONG`, `SET_POSITION_TARGET_LOCAL_NED`
  - Teste com QGroundControl via MAVProxy
- [ ] `nonce.rs` — `AtomicNonce` thread-safe para loops de controle
- [ ] Suporte a `no_std` (base para microcontroladores)
- [ ] Fuzzing do verificador de pacotes (cargo-fuzz)

### Tarefas de reconhecimento

- [ ] **Paper no IACR ePrint:**
  *"CleitonQ: Post-Quantum Authenticated C2 for MAVLink —
   ML-KEM-1024 Session Establishment and ML-DSA-87 Command Signing"*
  - Seções: threat model, protocol design, implementation, evaluation, security analysis
  - 8–10 páginas, formato IEEE

- [ ] Post em `discuss.ardupilot.org` com link para o paper
- [ ] Issue/Discussion em `github.com/mavlink/mavlink`:
  *"Proposal: PQC message authentication extension for MAVLink v3"*
- [ ] Post no Hacker News: "Show HN: CleitonQ — PQC for drone C2 in Rust"

**Entrega:** `v0.2.0` + paper no IACR ePrint

---

## Fase 3 — Padrão (v0.3) `[Q4 2025]`

**Objetivo técnico:** suporte a confidencialidade, `no_std`, STM32.

**Objetivo de reconhecimento:** RFC formal para MAVLink. Ser a referência citada.

**Objetivo financeiro:** primeira receita — grant ou consultoria.

### Tarefas técnicas

- [ ] Confidencialidade: AES-256-GCM sobre o canal autenticado
- [ ] Suporte `no_std + alloc` (STM32F4, Pixhawk hardware)
- [ ] Integração com `embassy` (async embedded Rust)
- [ ] `CleitonQSession` — objeto de sessão com estado encapsulado
- [ ] CLI `cleitonq-keygen` — ferramenta de geração e auditoria de chaves

### Tarefas de padrão

- [ ] **MAVLink RFC formal:**
  Proposta de extensão do protocolo MAVLink para PQC.
  Alvo: grupo de trabalho MAVLink no GitHub.
- [ ] Submissão para conferência:
  USENIX WOOT, IEEE S&P Workshop, ou ICRA Workshop on Security
- [ ] Contato direto com:
  - ArduPilot core team
  - PX4 Autopilot security track
  - UAVCAN/DroneCAN working group

### Tarefas financeiras

- [ ] **FAPESP PIPE** (se SP) ou **FINEP/EMBRAPII**:
  Proposta: "Segurança pós-quântica para comunicação de sistemas autônomos"
- [ ] Contato com empresas:
  - Shield AI (swarm autônomo, US)
  - Skydio (drones autônomos, US)
  - Embraer Defense (Brasil)
  - Avibras / Atech (defesa, Brasil)

**Entrega:** `v0.3.0` + RFC MAVLink + primeira proposta de financiamento submetida

---

## Fase 4 — Mercado (v1.0) `[Q2 2026]`

**Objetivo técnico:** produção-pronto, certificado, auditado.

**Objetivo de reconhecimento:** adoção por pelo menos um projeto open-source major
(ArduPilot ou PX4).

**Objetivo financeiro:** receita recorrente.

### Tarefas técnicas

- [ ] Auditoria de segurança por terceiros (Trail of Bits, NCC Group, ou equivalente)
- [ ] Certificação FIPS 140-3 (módulo criptográfico)
- [ ] Suporte a HSM (Nitrokey, YubiHSM) para proteção da signing key
- [ ] SDK Python (`pip install cleitonq`) via PyO3
- [ ] SDK C FFI para integração com sistemas legados

### Tarefas de mercado

- [ ] **Licença comercial:**
  MIT/Apache-2.0 para uso open-source.
  Licença comercial para integração em produtos proprietários.
- [ ] **Suporte enterprise:**
  SLA, integração assistida, atualizações de segurança prioritárias.
- [ ] **Treinamento:**
  Workshop de 2 dias: "Migrando sistemas autônomos para PQC"

**Entrega:** `v1.0.0` + primeiro cliente pagante

---

## Visão de longo prazo

```
2025 Q1  CleitonQ v0.1 no crates.io
2025 Q3  Paper no IACR ePrint + comunidades MAVLink/ArduPilot
2025 Q4  RFC MAVLink + grant submetido
2026 Q1  Adoção por ArduPilot ou PX4
2026 Q2  v1.0 auditado + primeiro cliente
2026 H2  Referência obrigatória quando mandato PQC entrar em vigor
```

O objetivo não é construir um produto de drone.
O objetivo é ser **o padrão de segurança que todos os drones vão precisar usar.**

---

*"A janela é 2025–2027. Quem define o padrão antes do mandato,
vira a referência depois."*

— Cleiton Augusto Correa Bezerra
