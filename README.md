# CPUMiner-Multi (@CanalQb)

> **Versão do fork:** 2.3.3 melhorada — correções, baixo consumo de hardware e documentação em PT-BR
> Feito com base nas [Master Rules v9.0](https://docs.google.com/document/d/1sTsRoAEWrU-1ltOMmUWyQ-18DFTmYl0R5UZc-QnNtCs)

Minerador de criptomoedas **multi-threaded** para CPU, fork do [cpuminer-multi](https://github.com/tpruvot/cpuminer-multi)
adaptado e melhorado pelo **@CanalQb**. Documentação 100% em português.

---

## TL;DR

- **Este binário minera SOMENTE o algoritmo CryptoNight** (família Monero/XMR e derivadas). Não minera Bitcoin diretamente — para BTC você precisa de outro minerador (veja o [TUTORIAL](TUTORIAL.md)).
- **Baixo consumo:** agora as threads respeitam a prioridade do sistema (`nice 19` por padrão), fixam cada thread a um núcleo (`affinity`) e aceitam `--throttle` para reduzir uso de CPU em desktops.
- **Vários bugs corrigidos:** vazamento de 2 MiB por thread, opção `-a` que era ignorada, buffer overflow potencial e divisão por zero no cálculo de hashrate.

> ⚠️ **Aviso Técnico:** mineração de criptomoedas é uma atividade de risco e, na maioria dos casos, **não é lucrativa em CPU** para moedas grandes. Este projeto tem fins **educacionais**. Teste sempre em ambiente controlado. O @CanalQb não se responsabiliza por danos, perdas financeiras ou bloqueios decorrentes do uso.

---

## Índice

- [O que este projeto faz (e o que NÃO faz)](#o-que-este-projeto-faz-e-o-que-não-faz)
- [Melhorias e correções desta versão](#melhorias-e-correções-desta-versão)
- [Dependências](#dependências)
- [Compilação](#compilação)
  - [Linux](#linux)
  - [Windows (MSYS2/MinGW)](#windows-msys2mingw)
  - [Docker](#docker)
- [Como usar](#como-usar)
- [Opções de linha de comando](#opções-de-linha-de-comando)
- [Reduzindo o consumo de hardware](#reduzindo-o-consumo-de-hardware)
- [Configuração por arquivo JSON](#configuração-por-arquivo-json)
- [Tutorial completo de mineração](#tutorial-completo-de-mineração)
- [FAQ](#faq)
- [Créditos e Licença](#créditos-e-licença)

---

## O que este projeto faz (e o que NÃO faz)

### Faz
- Minera moedas baseadas no algoritmo **CryptoNight**: Monero (XMR — versões antigas), Bytecoin (BCN), e derivadas.
- Conecta a pools que usam o protocolo **JSON-RPC 2.0** (estilo nodejs-pool / NiceHash / pools Monero antigos).
- Roda em **múltiplas threads** de CPU, com controle de prioridade, afinidade e throttle para não travar seu computador.

### NÃO faz
- ❌ **Não minera Bitcoin** (BTC). Bitcoin usa SHA-256d e exige ASICs — minerar BTC com CPU é tecnicamente impossível de ser lucrativo.
- ❌ **Não minera Litecoin, Dogecoin, Ethereum** — são algoritmos diferentes (scrypt, ethash, etc.).
- ❌ **Não minera tokens ERC-20/BEP-20** — tokens não são minerados (veja o TUTORIAL).
- ❌ **Não conversa com pools de stratum padrão** (ex.: pools de BTC/LTC). Este fork é limitado a JSON-RPC 2.0.

> 👉 Para moedas fora do CryptoNight, veja a seção [“Como minerar outras moedas”](TUTORIAL.md#como-minerar-outras-moedas-e-tokens) no tutorial.

---

## Melhorias e correções desta versão

### Bugs corrigidos
| # | Problema | Correção |
|---|----------|----------|
| 1 | Contexto CryptoNight (2 MiB/thread) alocado mas **nunca registrado** — vazamento de memória e `munmap(NULL)` na saída | Contexto agora é salvo no array global e liberado corretamente (`munmap`/`VirtualFree`/`free` conforme a alocação) |
| 2 | `-a`/`--algo` aceitava qualquer nome mas **ignorava** (o miner sempre rodava cryptonight) | Agora rejeita algoritmos não suportados com mensagem clara; só `cryptonight` é aceito |
| 3 | `memcpy(&rpc2_id, id, 64)` podia ler além do fim ou estourar o buffer de 64 bytes | Trocado por `strncpy` + terminação explícita |
| 4 | Divisão por zero no cálculo de hashrate (`thr_times` = 0) gerava NaN | Adicionada guarda `thr_times[i] > 0` |

### Baixo consumo de hardware
- **Prioridade `nice 19` por padrão** — o minerador cede CPU para seus outros programas. Antes, não-root rodava com prioridade normal e **roubava** o sistema.
- **Thread affinity ativo** — cada thread fixada a um núcleo reduz cache misses e consumo de energia (desative com `--no-affinity`).
- **`--throttle=N`** — pausa em microssegundos entre lotes de hashes. Em desktop/laptop, aumenta `N` e a temperatura/corrente caem na hora.
- **Hashmeter por thread reativado** — você vê o hashrate real de cada thread (desligue com `-q`).

### Build e configuração
- Dockerfile atualizado: `ubuntu:22.04`, repositório correto, `-march=native` opcional.
- `sources.list` atualizado para Ubuntu 22.04 (Jammy).
- `example-cfg.json` corrigido (mostrava `scrypt`, mas só cryptonight funciona).
- `autogen.sh` agora usa `autoreconf -fi` (mais robusto) com fallback manual.

---

## Dependências

- **libcurl** — [https://curl.se/libcurl/](https://curl.se/libcurl/)
- **jansson** — incluído no projeto (`compat/jansson`)
- **Compilador C** (gcc/clang), **make**, **autoconf/automake** (apenas para gerar o `configure`)
- **CPU com AES-NI** — obrigatório para desempenho razoável (o binário verifica e recusa CPU sem AES-NI)

---

## Compilação

### Linux

**Passo 1 — Instale as dependências de build.** No Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool pkg-config libcurl4-openssl-dev git
```

**Passo 2 — Clone o projeto.** Use o endereço oficial:

```bash
git clone https://github.com/canalqb/cpuminer-multi
cd cpuminer-multi
```

**Passo 3 — Gere o `configure`:**

```bash
./autogen.sh
```

**Passo 4 — Configure.** Para a sua máquina (o `-march=native` otimiza para sua CPU):

```bash
CFLAGS="-march=native" ./configure
```

Se sua CPU **não** tiver AES-NI, use `--disable-aes-ni` (fica bem mais lento):

```bash
CFLAGS="-march=native" ./configure --disable-aes-ni
```

**Passo 5 — Compile:**

```bash
make -j"$(nproc)"
```

**Resultado esperado:** um executável `minerd` na pasta do projeto. Verifique com `./minerd --help`.

**Erro comum:** `configure: error: Missing required libcurl >= 7.15.2` → falta o pacote `libcurl4-openssl-dev`. Instale e rode o `./configure` de novo.

### Windows (MSYS2/MinGW)

**Passo 1 — Instale o MSYS2** em [msys2.org](https://www.msys2.org/) e abra o **MINGW64** (não o MSYS).

**Passo 2 — Instale as ferramentas:**

```bash
pacman -S --needed base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-curl git autoconf automake libtool
```

**Passo 3 — Clone e compile:**

```bash
git clone https://github.com/canalqb/cpuminer-multi
cd cpuminer-multi
./autogen.sh
CFLAGS="-O3" ./configure
make
```

O binário `minerd.exe` será gerado. Você pode rodá-lo pelo MINGW64 ou pelo `cmd`.

### Docker

```bash
# build com flags genéricas (portável)
docker build -t cpuminer-multi .

# rodar apontando para o pool
docker run cpuminer-multi --url <URL_DO_POOL> --user <SUA_CARTEIRA.trabalhador> --pass x
```

Para otimizar para a CPU da máquina que compila:

```bash
docker build --build-arg MARCH=-march=native -t cpuminer-multi .
```

---

## Como usar

A forma mais comum de rodar é via pool com URL `stratum+tcp://`:

```bash
./minerd -o stratum+tcp://SEU_POOL.com:PORTA -u SUA_CARTEIRA.trabalhador -p x
```

O campo `-p x` normalmente é apenas `x` (senha padrão de pools).

Para testar sem conectar a nenhum pool (benchmark):

```bash
./minerd --benchmark -t 4
```

Isso roda 4 threads em modo offline e mostra o hashrate — ótimo para medir sua CPU.

---

## Opções de linha de comando

| Opção | Descrição |
|-------|-----------|
| `-o, --url=URL` | URL do servidor de mineração (use `stratum+tcp://`) |
| `-u, --user=USER` | Usuário/carteira do pool (formato `CARTEIRA.nome_do_worker`) |
| `-p, --pass=PASS` | Senha do pool (normalmente `x`) |
| `-O, --userpass=U:P` | Usuário:senha em um único argumento |
| `-t, --threads=N` | Número de threads (padrão: núcleos − 1) |
| `--priority=N` | Prioridade `nice` de −20 (mais CPU) a 19 (menos CPU). Padrão: **19** |
| `--throttle=N` | Pausa em µs entre lotes de hashes. `0` = desligado |
| `--no-affinity` | Desliga o pinning automático das threads aos núcleos |
| `-q, --quiet` | Desliga o hashmeter por thread |
| `-D, --debug` | Logs de debug |
| `-P, --protocol-dump` | Dump verboso do protocolo |
| `--benchmark` | Benchmark offline (sem pool) |
| `-c, --config=FILE` | Carrega configuração JSON |
| `--no-stratum` | Desliga suporte a stratum |
| `--no-longpoll` | Desliga long-polling |
| `--no-redirect` | Ignora redirecionamento de pool |
| `-x, --proxy=...` | Proxy HTTP/SOCKS |
| `-R, --retry-pause=N` | Segundos entre tentativas de reconexão |
| `-r, --retries=N` | Máx. de tentativas (padrão: infinito) |
| `-V, --version` | Mostra versão |
| `-h, --help` | Ajuda |

---

## Reduzindo o consumo de hardware

O consumo de CPU do minerador é proporcional a **threads × hashrate**. Para usar no dia a dia sem travar a máquina:

| Cenário | Comando sugerido |
|---------|------------------|
| Desktop (deixar o PC usável) | `-t 2 --priority 19 --throttle 2000` |
| Laptop (economizar bateria/calor) | `-t 1 --throttle 5000` |
| Servidor dedicado (máx. hashrate) | `-t <núcleos> --priority 0` |
| VPS com 2 núcleos | `-t 1 --throttle 0` |

Explicação de cada parâmetro:

- **`-t N`** define quantos núcleos entram. Padrão já é conservador (núcleos − 1).
- **`--priority 19`** (padrão) = menor prioridade possível. O sistema operacional roda seus outros programas primeiro; o miner só usa o que sobra.
- **`--throttle N`** insere uma pausa de `N` microssegundos após cada lote de hashes. Aumentar `N` reduz consumo de energia e temperatura, ao custo de hashrate menor.
- **`--no-affinity`** só é útil se você quiser que o sistema mova as threads (ex.: máquinas com muitos núcleos e jobs variáveis). Em geral, mantenha o affinity ligado.

---

## Configuração por arquivo JSON

Exemplo (`example-cfg.json`):

```json
{
  "url" : "stratum+tcp://SEU_POOL.com:PORT",
  "user" : "SUA_CARTEIRA.trabalhador",
  "pass" : "x",

  "algo" : "cryptonight",
  "threads" : "4",

  "priority" : "19",
  "throttle" : "0",
  "quiet" : true
}
```

Uso:

```bash
./minerd -c example-cfg.json
```

Qualquer opção de formato longo pode vir no JSON como string. Booleans usam `true`/`false`.

---

## Tutorial completo de mineração

👉 Veja o **[TUTORIAL.md](TUTORIAL.md)** — guia passo a passo em PT-BR que ensina:

- Como criar uma carteira e escolher um pool
- Como minerar **CryptoNight** (este minerador)
- Como minerar **Bitcoin e outras moedas** (qual minerador usar para cada algoritmo)
- Por que **tokens ERC-20/BEP-20 não são minerados**
- FAQ e erros comuns

---

## FAQ

**O minerador está dando “CPU does not have AES-NI”.**
Sua CPU não tem AES-NI (ou o binário foi compilado esperando isso). Recompile com `--disable-aes-ni`, mas o desempenho cai para ~1/3.

**Por que meu hashrate é zero / muito baixo?**
Verifique `-t` (número de threads), prioridade e se outro processo está consumindo CPU. No Windows, use o Gerenciador de Tarefas para confirmar que as threads estão ativas.

**O pool não aceita minhas shares.**
Confirme que o pool é compatível com CryptoNight **e** com JSON-RPC 2.0 (pools Monero antigos / nodejs-pool). Pools modernos de Monero usam RandomX e o protocolo padrão — este fork antigo não os atende.

**Dá para minerar Bitcoin com isso?**
Não. BTC usa SHA-256d e exige ASIC. Veja o TUTORIAL para alternativas.

**Isso vai danificar minha CPU?**
Mineração em CPU esquenta o processador e aumenta o desgaste. Use `--throttle`, `--priority 19` e monitorize a temperatura. Em laptop, evite deixar por muitas horas sem ventilação adequada.

---

## Créditos e Licença

- Fork original: [tpruvot/cpuminer-multi](https://github.com/tpruvot/cpuminer-multi) (Wolf), baseado no [LucasJones](https://github.com/lucasjones)'s cpuminer-multi.
- Adaptação, correções, otimizações de consumo e documentação PT-BR: **@CanalQb** ([canalqb.com.br](https://canalqb.com.br) / [YouTube](https://www.youtube.com/@canalqb)).
- Licença: **GPLv2** — veja [COPYING](COPYING).

Donativos (opcional):
- XMR: `42QWoLF7pdwMcTXDviJvNkWEHJ4TXnMBh2Cx6HNkVAW57E48Zfw6wLwDUYFDYJAqY7PLJUTz9cHWB5C4wUA7UJPu5wPf4sZ`
- BTC: `1WoLFumNUvjCgaCyjFzvFrbGfDddYrKNR`
