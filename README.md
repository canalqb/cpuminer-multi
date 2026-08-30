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
- Minera **Nerva (XNV) solo** com daemon oficial (CNA v6) — a única moeda CryptoNight com mineração ativa e pagamento real neste minerador. Também suporta **qualquer pool CryptoNight v0** com protocolo JSON-RPC 2.0 (opção "Outra derivada do CryptoNight" no menu).
- Conecta a pools que usam o protocolo **JSON-RPC 2.0** (estilo nodejs-pool / NiceHash / pools Monero antigos).
- Roda em **múltiplas threads** de CPU, com controle de prioridade, afinidade e throttle para não travar seu computador.

### NÃO faz
- ❌ **Não minera Bitcoin** (BTC). Bitcoin usa SHA-256d e exige ASICs — minerar BTC com CPU é tecnicamente impossível de ser lucrativo.
- ❌ **Não minera Litecoin, Dogecoin, Ethereum** — são algoritmos diferentes (scrypt, ethash, etc.).
- ❌ **Não minera tokens ERC-20/BEP-20** — tokens não são minerados (veja o TUTORIAL).
- ❌ **Não conversa com pools de stratum padrão** (ex.: pools de BTC/LTC). Este fork é limitado a JSON-RPC 2.0.
- ❌ **Não minera Nerva (XNV) com o `minerd`** — a Nerva usa CryptoNight-Adaptive v6 (incompatível com o CryptoNight v0 do `minerd`). A mineração Nerva é feita exclusivamente pelo daemon oficial `nervad.exe` (solo, sem pool).

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
| 5 | Compilação falhava no GCC 14+ com `static declaration of 'opt_no_affinity' follows non-static declaration` | Removido o `static` da declaração em `cpu-miner.c` (a variável já era `extern` em `miner.h`) |
| 6 | **Segfault no benchmark**: `applog("Total: %s H/s", hashrate)` passava um `double` para `%s` (espera `char*`) — comportamento indefinido e crash após o 1º hash | Valor formatado em string com `sprintf` antes do `applog` |

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

### Mineração Nerva (XNV) solo e carteira
- **Suporte oficial à Nerva (XNV)** — moeda solo, sem pool, via daemon oficial `nervad.exe`. **Atenção: o `minerd` (cpuminer) NÃO minera Nerva** — a Nerva usa CryptoNight-Adaptive v6 (8 MiB de scratchpad + programa aleatório), incompatível com o CryptoNight v0 (2 MiB) do `minerd`. Todo o hashrate sai do `nervad` com `--start-mining`. O script detecta o binário (pasta do projeto ou irmã `nerva-*`), sobe o daemon, espera sincronizar e mostra hashrate/altura/dificuldade ao vivo.
- **Geração de carteira real** (`--nerva --gerar-carteira`) — a partir da spend private key (hex ou inteiro decimal), deriva as chaves pública/privada e gera o endereço Nerva correto.
- **Consulta de saldo** (`--saldo`) — usa o `nerva-wallet-rpc` para importar as chaves privadas (a Nerva é privada; não dá para consultar só pelo endereço). Roda em **segundo plano**: mostra o % de sincronização e o valor aparece quando atinge 100%.
- **Contorno de DNS dos seeds** — em redes onde o daemon não resolve os seeds via DNS-over-TCP próprio, o script adiciona `--add-peer` com os IPs oficiais automaticamente.
- **Progresso compacto** — as linhas `Synced X/Y (Z%, W left)` do daemon são exibidas na mesma linha (`\r`), sem poluir o terminal.

### Multi-moeda com flag por moeda
- Cada moeda suportada tem um **flag CLI próprio**: `--nerva` (solo). Sem flag, a **primeira execução pergunta qual moeda minerar** com uma apresentação clara (modo SOLO/POOL, dificuldade, cotação, depósito mínimo e o comando de cada uma).
- Moedas que migraram de algoritmo (Zano-PoW, cryptonight-lite, K12, AstroBWT, CN-R, Argon2id, RandomX), sem liquidez real ou com mineração inviável (ETN — recompensa queimada, XMC — chain descontinuada) foram **removidas** — só ficam as mineráveis de verdade com este binário.

---

## Dependências

- **libcurl** — [https://curl.se/libcurl/](https://curl.se/libcurl/)
- **jansson** — incluído no projeto (`compat/jansson`)
- **Compilador C** (gcc/clang), **make**, **autoconf/automake** (apenas para gerar o `configure`)
- **CPU com AES-NI** — obrigatório para desempenho razoável (o binário verifica e recusa CPU sem AES-NI)

---

## Compilação

### Instalando o MinGW no Windows

**O que é MinGW?** É o conjunto de ferramentas que compila código C/C++ no Windows: o compilador `gcc`, o `make` e as bibliotecas (incluindo `libcurl`, obrigatória deste projeto). A forma mais fácil de ter tudo isso é instalar o **MSYS2**, um ambiente que entrega um shell Unix + MinGW64 no Windows.

**Opção A — Instalar o MSYS2 via `winget` (recomendado, sem navegador):**

```powershell
winget install --id MSYS2.MSYS2 --accept-source-agreements
```

Instala em `C:\msys64`. Para usar, abra o terminal **MINGW64**:

```powershell
C:\msys64\msys2_shell.cmd -mingw64
```

ou pelo menu Iniciar → **MSYS2 MINGW64**.

**Opção B — Instalar manualmente:** baixe o instalador em [msys2.org](https://www.msys2.org/), execute e avance com os padrões. Ao final, abra o **MINGW64**.

Depois de abrir o MINGW64, instale as ferramentas de build:

```bash
pacman -S --needed base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-curl git autoconf automake libtool
```

> `mingw-w64-x86_64-toolchain` traz `gcc` + `make`; `mingw-w64-x86_64-curl` traz a `libcurl`; `autoconf`/`automake`/`libtool` geram o `configure`. O `--needed` pula o que já estiver instalado.

Confira se ficou tudo certo (o `curl-config` prova que a libcurl está visível):

```bash
export PATH="/mingw64/bin:$PATH"
gcc --version | head -1
make --version | head -1
curl-config --version
```

### Instalando o MinGW/gcc no Linux

**O que é MinGW no Linux?** Para compilar este projeto nativamente no Linux você não precisa de "MinGW" em si — precisa do compilador `gcc` e das ferramentas de build. (MinGW é usado apenas para gerar executáveis `.exe` do Windows a partir do Linux, o que não é o caso aqui.)

**Debian/Ubuntu:**

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool pkg-config libcurl4-openssl-dev git
```

- `build-essential` → `gcc`, `g++`, `make`.
- `libcurl4-openssl-dev` → headers e lib da `libcurl` (obrigatória).
- `autoconf`/`automake`/`libtool`/`pkg-config` → geração do `configure`.

**Fedora/RHEL/CentOS:**

```bash
sudo dnf install -y gcc gcc-c++ make autoconf automake libtool pkgconfig libcurl-devel git
```

**Arch/Manjaro:**

```bash
sudo pacman -S --needed base-devel curl autoconf automake libtool pkg-config git
```

Confira:

```bash
gcc --version | head -1
make --version | head -1
curl-config --version
```

### Linux

**Passo 1 — Instale as dependências de build** (se ainda não as tem):

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

> **Importante (rodar fora do MINGW64):** o `minerd.exe` precisa das DLLs de runtime do MinGW (`libcurl-4.dll`, `libssl-3-x64.dll`, `libwinpthread-1.dll`, etc.). Elas ficam em `C:\msys64\mingw64\bin`. Se você abrir um `cmd`/PowerShell comum sem esse diretório no `PATH`, o Windows acusa erro de `libcurl-4.dll` ausente. Para rodar em qualquer terminal:
>
> ```bash
> # dentro do MINGW64, na pasta do projeto — copia todas as DLLs necessárias
> ldd minerd.exe | grep mingw64 | awk '{print $1}' | sort -u | while read dll; do cp "/mingw64/bin/$dll" .; done
> ```
>
> Depois disso, o `minerd.exe` roda de um `cmd` comum sem depender do MSYS2. (Este repositório já inclui essas DLLs junto do binário.)

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

### Rodando pelo script Python (`minerar.py`)

Se você tem **Python 3** instalado, o projeto inclui um `minerar.py` que localiza o binário, monta o comando e faz streaming da saída:

```bash
# Primeira execução: pergunta QUAL moeda minerar (menu com todas), carteira,
# pool etc. e salva em minerar.config.json
python minerar.py

# Nas próximas vezes, é só rodar de novo — mostra as moedas disponíveis
# e como consultá-las, espera 2 segundos e continua minerando
python minerar.py

# Benchmark local (sem pool)
python minerar.py --benchmark

# Ver a config salva (sem minerar)
python minerar.py --show

# Refazer a configuração do zero (pergunta a moeda de novo)
python minerar.py --setup

# Painel web ao vivo com hashrate/shares/pool (http://localhost:8080)
python minerar.py --dashboard

# --- Escolha direta da moeda por flag (cada uma tem a sua) ---

# Minerar Nerva (XNV) solo com o daemon oficial nervad.exe (sem pool)
python minerar.py --nerva

# Gerar carteira Nerva a partir da private key (hex ou inteiro decimal)
python minerar.py --nerva --gerar-carteira 0000000000000000000000000000000000000000000000000000000000000001
# Modo interativo (pergunta a chave)
python minerar.py --nerva --gerar-carteira

# Consultar saldo da carteira Nerva salva na config (sincroniza em 2º plano,
# mostra o % e exibe o saldo ao atingir 100%)
python minerar.py --saldo

# Com baixo consumo (desktop)
python minerar.py -o URL -u USER -p x -t 2 --priority 19 --throttle 2000
```

O script guarda **moeda, carteira, pool, worker, depósito mínimo para receber pagamento** e demais ajustes em `minerar.config.json`. Na primeira execução (ou com `--setup`) ele mostra um menu com as moedas suportadas — cada uma com o modo (SOLO/POOL), dificuldade, cotação, depósito mínimo e o comando próprio — e você digita o número da que quer minerar. Se o binário ainda não foi compilado, o script mostra os passos de build na tela. Encerre com `Ctrl+C`.

> **Moedas suportadas hoje:** Nerva (XNV — solo, sem pool, via `nervad`) e qualquer pool CryptoNight v0 com JSON-RPC 2.0 (opção "Outra derivada do CryptoNight" no menu). Moedas como Electroneum (ETN — recompensa queimada desde mar/2024, pools mortas), Monero Classic (XMC — chain descontinuada, pools offline) e outras que migraram de algoritmo ou sem liquidez foram removidas da lista.

> **Nerva (XNV)** é mineração **solo, sem pool** — o `minerar.py` detecta o `nervad.exe` do pacote oficial (https://nerva.one/#downloads) e roda a mineração sozinho, com status ao vivo (hashrate/altura via RPC do daemon). Durante o setup, digite `g` no campo do endereço para gerar uma carteira real a partir da sua spend key, ou use `python minerar.py --nerva --gerar-carteira`. Para consultar o saldo (a Nerva é privada — não dá para consultar pelo endereço), use `python minerar.py --saldo` com o daemon rodando e sincronizado.
>
> O progresso de sincronização da blockchain (`Synced X/Y …`) é exibido na mesma linha para não poluir o terminal, e a consulta de saldo roda em **segundo plano**: o script mostra o % de sincronização e continua respondendo, exibindo o valor da carteira somente quando a sincronização atinge 100%. Durante a mineração solo, se as chaves privadas estiverem salvas na config, o **saldo ao vivo** aparece na própria linha de status do relógio (a cada 60s) assim que o daemon sincroniza — sem precisar rodar `--saldo`.

### Onde instalar os arquivos da Nerva

Os comandos da Nerva (`--nerva`, `--nerva --gerar-carteira`, `--saldo`) precisam de dois executáveis do pacote oficial da Nerva:

| Arquivo | Para que serve |
|---------|----------------|
| `nervad.exe` | Daemon da Nerva — sincroniza a blockchain e faz a mineração SOLO |
| `nerva-wallet-rpc.exe` | Consulta de saldo (importa as chaves privadas da carteira) |

> Ambos vêm juntos no mesmo pacote oficial: **https://nerva.one/#downloads** (v0.3.0.0 ou mais novo). Basta baixar e extrair — um único download fornece os dois.

O `minerar.py` procura esses executáveis em **3 lugares, nesta ordem**:

1. **Na pasta do projeto** — cole os arquivos em `cpuminer-multi/` (mesma pasta do `minerar.py`):
   ```
   cpuminer-multi/
   ├── minerar.py
   ├── nervad.exe          ← copie aqui (ou na opção 3)
   └── nerva-wallet-rpc.exe
   ```
2. **No PATH do sistema** — se os executáveis já estiverem acessíveis pelo terminal.
3. **Em uma pasta irmã que comece com `nerva-`** — o local mais comum, já que o pacote baixado se chama `nerva-windows-x64-v0.3.0.0`:
   ```
   github/
   ├── cpuminer-multi/              ← projeto (minerar.py aqui)
   └── nerva-windows-x64-v0.3.0.0/  ← pasta irmã com nervad.exe e nerva-wallet-rpc.exe
   ```
   Basta deixar a pasta extraída ao lado do projeto — o script a encontra sozinho, sem copiar nada.

> **Dica:** se o script não encontrar os arquivos, ele imprime na tela exatamente onde colocar (`python minerar.py --nerva` mostra o caminho esperado). Se a pasta irmã não for encontrada, copie os dois `.exe` para dentro de `cpuminer-multi/`.

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

### Opções do `minerar.py`

Além das opções acima (que o script repassa ao minerador), o `minerar.py` aceita:

| Opção | Descrição |
|-------|-----------|
| `--setup` | Refazer a configuração do zero |
| `--show` | Mostrar a config salva (sem minerar) |
| `--benchmark` | Benchmark offline (ignora config e pool) |
| `--dashboard[=PORTA]` | Painel web ao vivo (padrão: porta 8080) |
| `--nerva` | Minera Nerva (XNV) solo com o `nervad.exe` (sem pool, sem minerd) |
| `--gerar-carteira[=HEX]` | Gera a carteira Nerva a partir da spend key (hex ou inteiro). Sem argumento, entra no modo interativo |
| `--saldo` | Consulta o saldo da carteira Nerva salva na config (sincroniza em 2º plano e exibe o valor ao chegar a 100%) |
| `--extra ...` | Argumentos adicionais passados direto ao `minerd` |

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
