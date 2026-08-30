# Tutorial de Mineração de Criptomoedas para CPU

**Aplicável especialmente ao cpuminer-multi do @CanalQb e demais mineradores de CPU.**

> **TL;DR:**
> - Mineração em CPU só é lucrativa para moedas específicas (Monero/RandomX, VerusCoin, etc.) — **não para Bitcoin**.
> - Cada moeda usa um algoritmo de hash diferente; você precisa do minerador certo para o algoritmo certo.
> - Tokens ERC-20/BEP-20 **não são minerados** — são emitidos por contratos inteligentes.
> - Este tutorial ensina os comandos reais, o que esperar de cada um, e o que fazer se der errado.

---

## Índice

1. [Conceitos fundamentais](#1-conceitos-fundamentais)
2. [O que você precisa para minerar](#2-o-que-você-precisa-para-minerar)
3. [CryptoNight — usando este cpuminer-multi](#3-cryptonight--usando-este-cpuminer-multi)
4. [Como minerar Bitcoin (BTC) e outras SHA-256d](#4-como-minerar-bitcoin-btc-e-outras-sha-256d)
5. [Como minerar outras moedas por algoritmo](#5-como-minerar-outras-moedas-por-algoritmo)
6. [Tokens — o que são e como obtê-los](#6-tokens--o-que-são-e-como-obtê-los)
7. [FAQ — erros comuns e soluções](#7-faq--erros-comuns-e-soluções)

---

## 1. Conceitos fundamentais

### O que é mineração?

Mineração é o processo de **validar transações** em uma blockchain resolvendo problemas matemáticos (hashes). O primeiro minerador que acha a solução recebe uma recompensa em moedas. Quanto mais hashes por segundo (hashrate) sua máquina produz, maior a chance de receber a recompensa.

### O que é um algoritmo de hash?

Cada blockchain usa um algoritmo específico para o cálculo de prova de trabalho (Proof of Work / PoW). Você precisa de um minerador que **entenda aquele algoritmo**:

| Algoritmo | Moedas | Melhor hardware |
|-----------|--------|-----------------|
| SHA-256d | Bitcoin (BTC), Bitcoin Cash (BCH) | ASIC (chip dedicado) |
| Scrypt | Litecoin (LTC), Dogecoin (DOGE) | ASIC |
| Ethash | Ethereum Classic (ETC) | GPU (placa de vídeo) |
| RandomX | Monero (XMR) moderno | **CPU** (AMD Ryzen, Intel) |
| CryptoNight | Monero antigo, Nerva (XNV — CNA v6), pools CryptoNight v0 | CPU (este minerador / nervad) |

**Regra de ouro:** CPU → moedas resistentes a ASIC (RandomX, CryptoNight, VerusHash). GPU → Ethash, KawPow. ASIC → SHA-256d, Scrypt. Não adianta usar a ferramenta errada.

### O que você precisa para minerar

1. **Uma carteira (wallet)** — endereço onde as moedas mineradas cairão.
2. **Um pool de mineração** — servidor que reúne o poder de hash de vários mineradores e divide a recompensa.
3. **Um minerador** — software que conecta sua máquina ao pool e faz os cálculos.

---

## 2. O que você precisa para minerar

### Passo 1: Crie uma carteira

Para receber pagamentos, você precisa de um endereço da moeda que vai minerar.

**Exemplo — Monero (XMR):**

1. Baixe a [Carteira Oficial do Monero](https://www.getmonero.org/downloads/) (GUI) ou crie uma conta em uma exchange (ex.: Binance, KuCoin) que suporte XMR.
2. Na carteira, vá em **Receber** e copie o endereço longo (começa com `4` no Monero).
3. Esse endereço é o que você usará no pool como `--user`.

**Exemplo — Bitcoin (BTC):**

1. Crie uma carteira (ex.: [Electrum](https://electrum.org/), [Trust Wallet](https://trustwallet.com/), ou exchange).
2. Copie o endereço BTC (começa com `1`, `3` ou `bc1`).

> ⚠️ **Aviso financeiro:** nunca compartilhe sua chave privada ou seed phrase. O endereço público (para receber) é a única informação que você passa ao pool.

### Passo 2: Escolha um pool

Cada moeda tem pools específicos. Para encontrar um pool ativo, pesquise: "melhores pools [moeda] 2025" ou sites como [miningpoolstats.stream](https://miningpoolstats.stream/).

| Moeda | Exemplo de pool | URL de conexão (stratum) |
|-------|-----------------|--------------------------|
| Monero (XMR) | SupportXMR | `stratum+tcp://pool.supportxmr.com:3333` |
| Bitcoin (BTC) | F2Pool | `stratum+tcp://btc.f2pool.com:1314` |
| Litecoin (LTC) | LitecoinPool | `stratum+tcp://litecoinpool.org:3333` |

**Cada pool informa:**
- **URL do stratum** — o endereço e porta para conectar.
- **Formato do usuário** — normalmente `CARTEIRA.nome_do_trabalhador`.

### Passo 3: Baixe o minerador certo

- Para **CryptoNight** (Monero antigo, Electroneum, Monero Classic): este cpuminer-multi.
- Para **RandomX** (Monero moderno): [XMRig](https://github.com/xmrig/xmrig) (muito mais rápido).
- Para **SHA-256d** (Bitcoin): ASIC com firmware próprio, ou [cgminer](https://github.com/ckolivas/cgminer) para testes.
- Para **Ethash** (ETC): [lolMiner](https://github.com/Lolliedieb/lolMiner-releases) ou [TeamRedMiner](https://github.com/todxx/teamredminer).

---

## 3. CryptoNight — usando este cpuminer-multi

> Este fork do @CanalQb suporta **apenas** CryptoNight com protocolo **JSON-RPC 2.0**. Pools modernos de Monero (RandomX) não funcionam aqui.

### Passo 3.0: Compilando o minerador (instalação do MinGW/gcc)

O projeto é código-fonte C — antes de rodar, você precisa de um compilador C e das bibliotecas. Isso varia por sistema operacional:

**Windows — instalar o MinGW (via MSYS2):**

O **MinGW** é o conjunto `gcc` + `make` + bibliotecas que compila código C no Windows. A maneira mais simples é instalar o **MSYS2**, que traz tudo:

```powershell
# Opção A: via winget (recomendado)
winget install --id MSYS2.MSYS2 --accept-source-agreements
```

> Opção B: baixe o instalador em https://www.msys2.org/ e execute com os padrões.

Depois, abra o terminal **MINGW64** (`C:\msys64\msys2_shell.cmd -mingw64` ou menu Iniciar) e instale as ferramentas:

```bash
pacman -S --needed base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-curl git autoconf automake libtool
```

Confira:

```bash
export PATH="/mingw64/bin:$PATH"
gcc --version | head -1
curl-config --version
```

**Linux — instalar o gcc/build-essential:**

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential autoconf automake libtool pkg-config libcurl4-openssl-dev git

# Fedora/RHEL/CentOS
sudo dnf install -y gcc gcc-c++ make autoconf automake libtool pkgconfig libcurl-devel git

# Arch/Manjaro
sudo pacman -S --needed base-devel curl autoconf automake libtool pkg-config git
```

**Compilar (qualquer sistema):**

```bash
git clone https://github.com/canalqb/cpuminer-multi
cd cpuminer-multi
./autogen.sh
CFLAGS="-O3" ./configure        # Linux otimizado: CFLAGS="-march=native"
make -j"$(nproc)"               # Windows: make (ou make -j8)
```

No Windows o binário gerado é `minerd.exe`; no Linux, `minerd`. Teste com `./minerd --help`.

> 💡 Dica: com Python 3 instalado, dá para usar o `minerar.py` do projeto — ele localiza o binário, monta o comando certo e mostra a saída em tempo real. Se o binário não existir, o script imprime estes mesmos passos.

### Passo 3.1: Conecte ao pool

```bash
./minerd -o stratum+tcp://SEU_POOL.com:PORTA -u SUA_CARTEIRA.trabalhador -p x
```

**O que esse comando faz:**
- `-o` aponta o minerador para o pool via protocolo stratum+tcp.
- `-u` informa sua carteira e o nome do worker (você cria um nome qualquer, como "pc01").
- `-p x` é a senha — a maioria dos pools ignora, use `x`.

**Resultado esperado:**
```
[2025-01-10 14:30:01] Using JSON-RPC 2.0
[2025-01-10 14:30:01] 4 miner threads started, using 'cryptonight' algorithm (priority 19, throttle 0µs, affinity on).
[2025-01-10 14:30:05] thread 0: 256 hashes, 42.50 H/s
[2025-01-10 14:30:05] thread 1: 248 hashes, 41.20 H/s
[2025-01-10 14:30:05] accepted: 1/1 (100.00%), 168.30 H/s (yay!!!)
```

Se você **não** vir o log "Using JSON-RPC 2.0", o binário pode ser de outro fork. Compile o nosso.

**Erro comum:** `HTTP request failed: Empty reply from server` → a URL do pool está errada ou o pool não fala JSON-RPC 2.0. Verifique a URL e a porta.

### Passo 3.2: Benchmark (teste sem pool)

```bash
./minerd --benchmark -t 4
```

Útil para medir o hashrate da sua CPU sem precisar de conexão. O resultado final aparece como "Total: X H/s".

### Passo 3.3: Baixo consumo (desktop/laptop)

```bash
./minerd -o stratum+tcp://... -u ... -p x -t 2 --priority 19 --throttle 2000
```

- `-t 2` usa só 2 threads (numa CPU de 4+ núcleos, o PC continua responsivo).
- `--priority 19` faz o sistema operacional dar prioridade a outros programas.
- `--throttle 2000` insere pausa de 2 ms entre lotes de hash — reduz aquecimento.

**Resultado esperado:** o PC continua navegável; o minerador usa "o que sobra" de CPU.

### Passo 3.4: Rodando em background (Linux)

```bash
./minerd -B -o stratum+tcp://... -u ... -p x
```
A flag `-B` faz o processo rodar em segundo plano (daemon).

### Passo 3.5: Minerar Nerva (XNV) solo (sem pool)

Nerva (XNV) é uma moeda **solo, sem pool** — cada minerador roda um nó completo e compete individualmente. O `minerar.py` do projeto gerencia tudo com o flag `--nerva`.

> **ATENÇÃO:** o `minerd.exe` (cpuminer-multi) **NÃO minera Nerva**. A Nerva usa **CryptoNight-Adaptive v6 (CNA v6)** desde o Hard Fork 13 (Julho/2026): 8 MiB de scratchpad + programa aleatório por bloco + acesso a memória dependente. O `minerd` deste projeto só implementa **CryptoNight v0** (2 MiB, fixo). Os algoritmos são **incompatíveis**.
>
> Todo o hashrate para Nerva vem do **`nervad.exe`** com `--start-mining`. O daemon sincroniza a blockchain E minera ao mesmo tempo. O `minerar.py` configura threads, afinidade e prioridade no próprio daemon.

### Passo 3.6: Pools CryptoNight v0 personalizadas

Além da Nerva (solo), o `minerar.py` permite minerar em **qualquer pool CryptoNight v0** com protocolo JSON-RPC 2.0 (opção "Outra derivada do CryptoNight" no menu). Não há flag dedicada — basta escolher a opção no menu ou digitar o nome.

| Moeda | Modo | Como selecionar |
|-------|------|-----------------|
| Nerva (XNV) | SOLO | `python minerar.py --nerva` |
| Pool CryptoNight v0 (custom) | POOL | menu → "Outra derivada do CryptoNight" |

Sem flag nenhuma, a **primeira execução mostra um menu** com as moedas suportadas — cada uma com modo (SOLO/POOL), dificuldade, cotação e depósito mínimo — e pergunta qual você quer minerar (basta digitar o número). Depois de escolhida, ela segue o fluxo de configuração específico daquela moeda (solo pede endereço/threads; pool pede endereço, worker, URL e senha do pool). Tudo é salvo em `minerar.config.json`.

Para pool, escolha a opção no menu e informe os dados do pool quando perguntado:

```bash
python minerar.py
# menu → "Outra derivada do CryptoNight"
# → pergunta endereço, worker, URL do pool (stratum+tcp://...), threads...
```

> **Por que não há mais ETN e XMC na lista?** As moedas CryptoNight v0 legadas ficaram **inviáveis de minerar**:
>
> - **Electroneum (ETN)** — a rede migrou para a "Electroneum Smartchain" (IBFT/PoA, sem mineração). A legacy chain (PoW) ainda usa CryptoNight v0, mas desde o bloco 1.806.749 (mar/2024, HF11) **toda a recompensa vai para um burn address** — o minerador não recebe nada. As pools históricas (easyhash, spacepools, etnpool, nanopool) estão **fora do ar**.
> - **Monero Classic (XMC)** — a chain v1 (CryptoNight v0) está sendo **descontinuada** em favor do XMC 3.0/4.0 (**RandomX**, incompatível com o `minerd`). As pools tradicionais (`pool.moneroclassic.org`, tpool.io) estão offline ou inacessíveis.
>
> Se você conhecer uma **pool CryptoNight v0 ativa**, informe a URL que o `minerar.py` aceita via menu (opção custom) — e podemos adicioná-la como opção fixa.

#### Onde instalar os arquivos da Nerva

Os comandos da Nerva precisam de dois executáveis do pacote oficial (baixe **um** pacote em https://nerva.one/#downloads, v0.3.0.0+ — os dois vêm juntos):

| Arquivo | Para que serve |
|---------|----------------|
| `nervad.exe` | Daemon da Nerva — sincroniza a blockchain e faz a mineração SOLO |
| `nerva-wallet-rpc.exe` | Consulta de saldo (importa as chaves privadas da carteira) |

O `minerar.py` procura esses executáveis em **3 lugares, nesta ordem**:

1. **Na pasta do projeto** — cole os arquivos em `cpuminer-multi/` (mesma pasta do `minerar.py`):
   ```
   cpuminer-multi/
   ├── minerar.py
   ├── nervad.exe
   └── nerva-wallet-rpc.exe
   ```
2. **No PATH do sistema** — se os executáveis já estiverem acessíveis pelo terminal.
3. **Em uma pasta irmã que comece com `nerva-`** — o local mais comum, pois o pacote baixado já vem assim:
   ```
   github/
   ├── cpuminer-multi/              ← projeto (minerar.py aqui)
   └── nerva-windows-x64-v0.3.0.0/  ← pasta irmã com nervad.exe e nerva-wallet-rpc.exe
   ```
   Basta deixar a pasta extraída ao lado do projeto — o script a encontra sozinho.

> Se o script não encontrar os arquivos, ele imprime na tela exatamente onde colocar. Na dúvida, copie os dois `.exe` para dentro de `cpuminer-multi/`.

#### Rodar

1. Baixe e extraia o pacote oficial (veja acima onde colocar).
2. Rode:

```bash
python minerar.py --nerva
```

Na primeira vez ele pergunta o endereço da carteira, threads, etc. e salva a config. Nas seguintes, `python minerar.py` já detecta que é Nerva e usa o `nervad.exe` automaticamente.

> **Gerar carteira real a partir da private key:** a Nerva é uma moeda de privacidade — para receber e consultar saldo você precisa das chaves privadas, não apenas do endereço público. Use:
>
> ```bash
> # Geração interativa (pergunta a spend key e gera o endereço real)
> python minerar.py --nerva --gerar-carteira
>
> # Direto pela linha de comando (spend key em hex)
> python minerar.py --nerva --gerar-carteira 0000000000000000000000000000000000000000000000000000000000000001
> ```
>
> O script aceita a spend key em **hex** (64 caracteres) ou **inteiro decimal**, ajusta com zeros à esquerda e deriva o endereço real + chaves pública/privada. Ele pergunta se você quer salvar na config, consultar o saldo e iniciar a mineração.

O script inicia o daemon com `--start-mining`, faz polling do RPC (porta 17566) e mostra hashrate/altura/dificuldade no terminal a cada 60s. Durante a sincronização o relógio mostra `altura X/Y (Z%)`; depois de sincronizar, se as chaves privadas estiverem na config, o **saldo ao vivo** é exibido na mesma linha. O `--dashboard` também funciona para Nerva e mostra o saldo (total e disponível) no painel web. Se o daemon encerrar com erro, o script lista as causas comuns (porta em uso, endereço inválido, rede).

> **Sincronização:** a primeira execução baixa a blockchain (pós-HF13, sync rápido com checkpoints). O daemon só minera de verdade após sincronizar.
>
> **Problema de DNS:** em algumas redes o daemon não consegue resolver os seeds via DNS-over-TCP próprio. O script já contorna isso adicionando `--add-peer` com os IPs dos seeds oficiais automaticamente.
>
> **Progresso compacto:** as linhas `Synced X/Y (Z%, W left)` do daemon aparecem na mesma linha (sobrescrevendo a anterior), para não encher o terminal.

**Consultar saldo da carteira Nerva:** como a Nerva é uma moeda de privacidade, o saldo não pode ser obtido pelo endereço público. Se você gerou a carteira pelo script (as chaves privadas estão salvas na config), pode consultar o saldo com:

```bash
python minerar.py --saldo
```

A consulta usa o `nerva-wallet-rpc.exe` (mesmo pacote do `nervad.exe`) para importar as chaves e sincronizar com o daemon local. Ela roda em **segundo plano**: o script mostra o % de sincronização (altura atual vs alvo) e **não trava** — você pode seguir para a mineração enquanto isso. O saldo total e desbloqueado só é exibido quando a sincronização atinge 100%.

> **Trocar a carteira não interrompe o daemon:** se você gerar uma nova carteira com outra private key, o daemon (blockchain) continua sincronizado — apenas a consulta de saldo reinicia com as novas chaves. O saldo mínimo para receber pagamento é de **40 XNV** por bloco (mecanismo anti-dust).

> **Atenção:** a primeira execução baixa a blockchain (pós-HF13, sync rápido com checkpoints). O daemon só minera de verdade após sincronizar.

---

## 4. Como minerar Bitcoin (BTC) e outras SHA-256d

**Bitcoin usa SHA-256d.** Desde ~2013, ASICs (circuitos dedicados) dominaram a mineração de BTC. Hoje:

- **CPU:** 0% de chance de achar um bloco sozinho — você nunca receberá recompensa.
- **GPU:** também inviável — ASICs são milhares de vezes mais rápidos.
- **ASIC:** único hardware que funciona (Antminer S19, Whatsminer M50, etc.).

### Para minerar BTC com ASIC:

1. Compre um ASIC (ex.: Antminer S19, usado, ~R$ 2.000–5.000).
2. Configure o pool no painel do ASIC: URL `stratum+tcp://btc.f2pool.com:1314`, worker `CARTEIRA.worker1`.
3. O ASIC minera sozinho 24h/dia.

### Para testar SHA-256d com CPU (apenas educativo):

Você pode usar o [cpuminer-opt](https://github.com/JayDDee/cpuminer-opt) ou [bfgminer](https://github.com/ckolivas/bfgminer) em CPU, mas **não espere lucro**:

```bash
# Apenas ilustrativo — não lucrativo
./cpuminer -a sha256d -o stratum+tcp://pool.bitcoin.com:3333 -u SEU_ENDERECO -p x
```

> ⚠️ **Nota técnica:** minerar BTC com CPU gasta eletricidade que custa mais do que o Bitcoin que você mineraria em milhares de anos. Faça apenas para aprender.

---

## 5. Como minerar outras moedas por algoritmo

Tabela prática de **algoritmo → minerador → moeda**:

| Algoritmo | Moedas | Minerador recomendado | Hardware |
|-----------|--------|-----------------------|----------|
| **SHA-256d** | Bitcoin (BTC), Bitcoin Cash (BCH), eCash (XEC) | ASIC (Antminer, Whatsminer) | ASIC |
| **Scrypt** | Litecoin (LTC), Dogecoin (DOGE), Bellcoin | ASIC, ou GPU (mineradores antigos) | ASIC > GPU |
| **Ethash (ETCHash)** | Ethereum Classic (ETC), EtherGem (EGEM) | lolMiner, TeamRedMiner, NBMiner | GPU (AMD/NVIDIA) |
| **KawPow** | Ravencoin (RVN) | lolMiner, TeamRedMiner | GPU |
| **RandomX** | Monero (XMR) moderno | XMRig | **CPU** (AMD Ryzen é o melhor) |
| **CryptoNight** | Monero (XMR) antigo, Nerva (XNV — CNA v6), pools CryptoNight v0 | **cpuminer-multi** (este!) / nervad | CPU |
| **VerusHash** | VerusCoin (VRSC) | VerusMiner, XMRig | **CPU** (Android até!) |
| **Yespower** | Yenten (YTN), Safecoin (SAFE) | cpuminer-opt | CPU |
| **GhostRider** | Raptoreum (RTM) | cpuminer-opt | CPU |

### Como escolher:

1. Pesquise moedas que usam algoritmo **resistente a ASIC** (RandomX, VerusHash, Yespower, GhostRider) — essas ainda são mineráveis em CPU.
2. Veja se a moeda tem pool ativo e liquidez em exchange (para vender o que minerar).
3. Escolha o minerador correspondente da tabela acima.

---

## 6. Tokens — o que são e como obtê-los

### Tokens NÃO são minerados

Diferente de Bitcoin ou Monero, **tokens** (ERC-20, BEP-20, SLP, TRC-20) funcionam sobre uma blockchain existente:

- **ERC-20** (USDT, UNI, LINK) → rodam sobre Ethereum.
- **BEP-20** (CAKE, BNB — versão BSC) → rodam sobre BNB Smart Chain.
- **SPL** (USDC, SRM) → rodam sobre Solana.

**Esses tokens não têm blockchain própria.** Eles são emitidos por contratos inteligentes. A única forma de "criar" tokens novos é escrevendo um contrato e pagando a taxa de gas da rede. Mineração não resolve hashes para tokens.

### Como obter tokens

1. **Comprar em exchange** — Binance, Mercado Bitcoin, Coinbase.
2. **Staking** — travar cripto em um protocolo DeFi e receber tokens como recompensa.
3. **Liquidity Mining** — fornecer liquidez a um pool DEX e ganhar tokens do protocolo.
4. **Airdrops** — receber tokens gratuitos por ter interagido com um projeto (ex.: Arbitrum, zkSync).
5. **Faucets** — sites que distribuem quantias mínimas para teste.

### Posso minerar tokens?

Não. Você minera a **moeda nativa** da blockchain (ETH na Ethereum, BNB na BSC, SOL na Solana) e depois pode trocar por tokens em uma exchange ou DEX. Se alguém promete que você pode "minerar token X" diretamente com CPU, é **golpe**.

---

## 7. FAQ — erros comuns e soluções

**"CPU does not have AES-NI"**
Sua CPU não tem instruções AES-NI necessárias para o CryptoNight. Soluções:
1. Recompile com `--disable-aes-ni` (fica 3× mais lento).
2. Troque para uma CPU que tenha AES-NI (qualquer Intel Core i3+ de 2010+ ou AMD Ryzen).

**"Stratum connection timed out"**
O pool não respondeu dentro de 600 segundos. Causas:
- Firewall bloqueando a porta (portas comuns: 3333, 4444, 5555).
- Pool offline ou URL errada.
- Internet instável.

**"JSON decode failed"**
O pool devolveu algo que não é JSON. Pode ser:
- Proxy HTTP no meio atrapalhando.
- Pool que não suporta JSON-RPC 2.0 (tente outro pool).

**"HTTP request failed: Empty reply from server"**
O pool recusou a conexão. Verifique:
- A URL começa com `stratum+tcp://` (não `http://`).
- A porta está correta.
- O pool está online (use `ping`).

**Hashrate oscilando muito**
Normal em CPUs com throttling térmico. Soluções:
- Aumente `--throttle` para reduzir aquecimento.
- Melhore a ventilação do gabinete.
- Em notebook, use uma base com cooler.

**"accepted: 0/1 (0.00%)"**
Suas shares estão sendo rejeitadas. Motivos:
- Carteira errada no `--user`.
- Dificuldade do pool muito baixa para seu hashrate (raro).
- Pool incompatível com JSON-RPC 2.0.

**O que significa "H/s" e como comparar?**
- **H/s** = hashes por segundo.
- **kH/s** = 1.000 H/s, **MH/s** = 1.000.000 H/s.
- **GH/s** = 1.000.000.000 H/s (ASICs de BTC fazem > 100 TH/s — 100 trilhões de hashes/s).
- Nosso minerador faz dezenas a centenas de H/s em CryptoNight. Para BTC, um ASIC faz trilhões. Por isso CPU não compete com ASIC em SHA-256d.

---

## Referências e links úteis

- [Lista de pools de mineração](https://miningpoolstats.stream/)
- [Calculadora de lucratividade](https://www.whattomine.com/)
- [Repositório do cpuminer-multi (@CanalQb)](https://github.com/canalqb/cpuminer-multi)
- [XMRig — minerador RandomX (Monero moderno)](https://github.com/xmrig/xmrig)
- [Documentação oficial do Bitcoin](https://bitcoin.org/en/developer-documentation)
- [Paper Monero — CryptoNight](https://www.getmonero.org/library/0-Overview/)

---

*Tutorial produzido pelo @CanalQb com base nas Master Rules v9.0 — Protocolo de Profundidade Tutorial (Seção 3.2).*