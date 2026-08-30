#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
minerar.py — Executa o CPUMiner-Multi (@CanalQb)

Produto do CanalQB — https://canalqb.com.br
Se quiser mais ferramentas, tutoriais e suporte, acesse o site.

Primeira execução: o script PERGUNTA o que é preciso para minerar
(endereço da carteira, pool, worker, threads, etc.) e salva tudo em
`minerar.config.json` na pasta do projeto. Nas execuções seguintes ele
carrega a configuração salva e inicia a mineração direto.

Uso:
    python minerar.py                # usa a config salva (ou configura na 1ª vez)
    python minerar.py --setup        # reconfigura do zero
    python minerar.py --show         # mostra a config salva (sem minerar)
    python minerar.py --benchmark    # benchmark offline (ignora a config)
    python minerar.py --dashboard    # abre painel web local (http://localhost:8080)
    python minerar.py --nerva        # minera Nerva (XNV) solo com o nervad.exe

Opções que sobrescrevem a config salva naquele run:
    -o URL -u USER -p PASS -t N --priority N --throttle N
    --no-affinity -q -D  (e --extra para o que mais precisar)
"""

import argparse
import atexit
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Diretório do projeto = pasta onde este script está
PROJETO_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJETO_DIR, "minerar.config.json")

BIN_WIN = "minerd.exe"
BIN_LINUX = "minerd"

# Nerva (XNV) — mineração SOLO com o daemon oficial (sem pool e sem o minerd).
# Pacote oficial: https://nerva.one/#downloads  (basta ter o nervad.exe)
NERVA_BIN_WIN = "nervad.exe"
NERVA_RPC_PORT = 17566            # RPC JSON do nervad (padrão da mainnet)
NERVA_DATA_DIR = os.path.join(PROJETO_DIR, "nerva-data")  # blockchain local
# Seeds P2P da Nerva (resolvidos manualmente dos registros TXT de seed.nerva.one
# para contornar falha do DNS-over-TCP do daemon em algumas redes).
NERVA_SEED_PEERS = ["74.208.52.101:17565", "185.23.5.186:17565"]
NERVA_WALLET_RPC_PORT = 17568  # porta RPC para consulta de saldo (nerva-wallet-rpc; 17567 é usada pelo nervad)

DEFAULT_PASS = "x"
DEFAULT_PRIORITY = 19


# ---------------------------------------------------------------------------
# Helpers de terminal
# ---------------------------------------------------------------------------

def perguntar(texto, padrao=""):
    """Pergunta ao usuário e devolve o valor digitado (ou o padrão)."""
    if padrao:
        valor = input(f"{texto} [{padrao}]: ").strip()
        return valor if valor else padrao
    while True:
        valor = input(f"{texto}: ").strip()
        if valor:
            return valor
        print("  [aviso] Não pode ficar vazio. Digite um valor.")


def perguntar_int(texto, padrao, minimo=1, maximo=None):
    """Pergunta um número inteiro, validando intervalo."""
    rotulo = f"{texto} [{padrao}]: " if padrao is not None else f"{texto}: "
    while True:
        valor = input(rotulo).strip()
        if not valor and padrao is not None:
            valor = str(padrao)
        try:
            n = int(valor)
        except ValueError:
            print("  [aviso] Digite um número inteiro.")
            continue
        if n < minimo or (maximo is not None and n > maximo):
            limite = f"de {minimo} a {maximo}" if maximo else f"maior ou igual a {minimo}"
            print(f"  [aviso] Valor deve ser {limite}.")
            continue
        return n


def perguntar_sn(texto, padrao="s"):
    """Sim/Não. Padrão 's' = sim, 'n' = não."""
    opcoes = {"s": True, "sim": True, "y": True, "yes": True,
              "n": False, "nao": False, "não": False, "no": False}
    rotulo = f"{texto} [s/N]: " if padrao == "n" else f"{texto} [S/n]: "
    while True:
        valor = input(rotulo).strip().lower() or padrao
        if valor in opcoes:
            return opcoes[valor]
        print("  [aviso] Responda s (sim) ou n (não).")


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

def config_padrao():
    cores = os.cpu_count() or 2
    return {
        "coin": "",         # moeda escolhida (CryptoNight family)
        "address": "",      # endereço/carteira da moeda
        "worker": "worker", # apelido da máquina no pool
        "url": "",          # pool: stratum+tcp://HOST:PORTA
        "pass": DEFAULT_PASS,
        "threads": max(1, cores - 1),
        "priority": DEFAULT_PRIORITY,
        "throttle": 0,
        "no_affinity": False,
        "quiet": False,
        "debug": False,
        "payout_min": "",  # saldo mínimo para receber pagamento (pool ou exchange)
        "nerva_threads": max(1, cores - 1),  # threads usadas pelo nervad (solo)
        "nerva_affinity": True,  # fixa threads nos núcleos físicos
        "nerva_bg": False,       # mineração só em segundo plano (PC ocioso)
        "nerva_spend_key": "",   # spend privada (para consultar saldo Nerva)
        "nerva_view_key": "",    # view privada (para consultar saldo Nerva)
    }


# Lista de moedas da família CryptoNight que AINDA EXISTEM com cotação
# verificada em CoinGecko (CG) ou CoinMarketCap (CMC). Formato FLEXÍVEL:
# (nome), (nome, depósito_mínimo) ou (nome, nota, depósito_mínimo) — o
# script normaliza tudo. Dificuldade/cotação podem ficar no próprio nome.
# O depósito mínimo é um valor SUGERIDO (padrão de pools típicas);
# confirme o valor da sua pool antes de minerar.
# IMPORTANTE — este binário minera SOMENTE cryptonight ORIGINAL (v0):
#   * Grupo 1 = dá para minerar AQUI (cryptonight original).
#   * Grupo 2 = existem e têm valor, mas exigem outro algoritmo
#               (cryptonight-lite, Zano-PoW, AstroBWT...) — NÃO funcionam
#               com este binário.
#   * Grupo 3 = existem (página de cotação), mas volume ~zero —
#               sem liquidez, a moeda minerada não vale nada.
# Moedas delistadas ou sem página de cotação foram REMOVIDAS.
MOEDAS_CRYPTONIGHT = [
    # Grupo 1 — mineráveis com este binário (cryptonight original)
    ("Monero (XMR) - Muito alta - CG #16 · US$8,8 bi · só pools antigas pré-RandomX · depósito mín.: 0,1 XMR",
     "0,1 XMR"),
    ("Electroneum (ETN) - Média - CG #1027 · US$13 mi · CryptoNight original · depósito mín.: 100 ETN",
     "100 ETN"),
    ("Monero Classic (XMC) - Baixa - CMC · vol ~US$16 mil/dia · CryptoNight original · depósito mín.: 1 XMC",
     "1 XMC"),
    ("Sumokoin (SUMO) - Baixa - CMC · vol ~US$3 mil/dia · confirme variante na pool · depósito mín.: 1 SUMO",
     "1 SUMO"),
    ("Lethean (LTHN) - Baixa - CMC · vol ~US$1 mil/dia · CryptoNight original · depósito mín.: 1 LTHN",
     "1 LTHN"),
    # Grupo 2 — existem com valor, mas exigem algoritmo NÃO suportado aqui
    ("Zano (ZANO) - Média - CG #227 · US$125 mi · Zano-PoW (não suportado aqui) · depósito mín.: 1 ZANO",
     "1 ZANO"),
    ("Aeon (AEON) - Média - CG #1018 · US$13 mi · cryptonight-lite (não suportado aqui) · depósito mín.: 1 AEON",
     "1 AEON"),
    ("Nerva (XNV) - Baixa - CG #2500 · US$1,5 mi · SOLO, sem pool (nervad/NervaOne) · CNA v6 (não suportado aqui) · saldo mín.: 40 XNV",
     "40 XNV"),
    ("Dero (DERO) - Baixa - CG #5299 · US$107 mil · AstroBWT (não é mais CryptoNight) · depósito mín.: 0,1 DERO",
     "0,1 DERO"),
    # Grupo 3 — existem (cotação), mas sem liquidez real
    ("Karbo (KRB) - Baixa - CG #4596 · vol ~US$3/dia · atividade incerta · depósito mín.: 1 KRB",
     "1 KRB"),
    ("ArQmA (ARQ) - Baixa - CMC · sem volume · atividade incerta · depósito mín.: 10 ARQ",
     "10 ARQ"),
    ("Conceal (CCX) - Baixa - CG #6108 · vol ~US$63/dia · atividade incerta · depósito mín.: 1 CCX",
     "1 CCX"),
    ("TurtleCoin (TRTL) - Baixa - CMC · vol ~US$20/dia · atividade incerta · depósito mín.: 10.000 TRTL",
     "10.000 TRTL"),
    ("Bytecoin (BCN) - Baixa - CG · cap US$0 · atividade incerta · depósito mín.: 10 BCN",
     "10 BCN"),
    ("Dashcoin (DSH) - Baixa - CMC · sem mercados ativos · atividade incerta · depósito mín.: 1 DSH",
     "1 DSH"),
    ("Outra derivada do CryptoNight", "—", ""),
]


def _normalizar_moeda(item):
    """Normaliza uma entrada da lista: devolve (nome, nota, payout).

    Aceita (nome), (nome, payout) ou (nome, nota, payout) — assim a lista
    pode ser editada à vontade sem quebrar o script.
    """
    if not isinstance(item, (tuple, list)):
        item = (item,)
    item = [str(x) for x in item]
    if len(item) == 1:
        return (item[0], "", "")
    if len(item) == 2:
        # Formato atual: (nome com tudo, depósito mínimo)
        return (item[0], "", item[1])
    return (item[0], item[1], item[2])


# Lista normalizada usada pelo script (nome, nota, payout)
MOEDAS = [_normalizar_moeda(m) for m in MOEDAS_CRYPTONIGHT]


def escolher_moeda():
    """Exibe as moedas compatíveis numeradas e pergunta qual o usuário quer minerar."""
    print("\nMoedas compatíveis com este minerador (CryptoNight):")
    print("  Dificuldade estimada (qualitativa): Muito alta ▸ Alta ▸ Média ▸ Baixa")
    print("-" * 60)
    for i, (moeda, nota, _) in enumerate(MOEDAS, 1):
        print(f"  {i:2d}. {moeda}")
        if nota and nota != "—":
            print(f"      {nota}")
    print("-" * 60)
    print("  (digite o número da moeda ou o nome personalizado)")
    print()

    while True:
        valor = input("Moeda: ").strip()
        if not valor:
            print("  [aviso] Escolha uma moeda da lista.")
            continue
        # Verifica se é número da lista
        try:
            idx = int(valor)
            if 1 <= idx <= len(MOEDAS):
                return MOEDAS[idx - 1][0]
        except ValueError:
            pass
        # Nome personalizado — aceita
        return valor


def sugestao_payout(coin):
    """Devolve o depósito mínimo sugerido da moeda (ou '' se não houver)."""
    for nome, _, payout in MOEDAS:
        if nome == coin:
            return payout
    return ""


def validar_address(address, coin):
    """Validações básicas do endereço — avisos, não bloqueio."""
    if len(address) < 20:
        print(f"  [aviso] Endereço muito curto ({len(address)} chars). "
              "Endereços CryptoNote costumam ter ~95 caracteres.")
    if coin.startswith("Monero (XMR)") and not address.startswith("4"):
        print("  [aviso] Endereços Monero (XMR) geralmente começam com '4'.")
    if "Bytecoin" in coin and not address.startswith("2"):
        print("  [aviso] Endereços Bytecoin (BCN) geralmente começam com '2'.")


# ---------------------------------------------------------------------------
# Validação de endereço Nerva (XNV)
# Endereço mainnet = varint(0x3800) + spend(32) + view(32) + keccak256[:4]
# Base58 é o do Monero: blocos de 8 bytes -> 11 chars (não é número inteiro).
# ---------------------------------------------------------------------------
_ALPHABET58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_ENC_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11]  # bytes -> chars do bloco
_B58_FULL = 8
_B58_FULL_ENC = 11
_B58_REV = {c: i for i, c in enumerate(_ALPHABET58)}


def _rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak256(data):
    """Keccak-256 puro (mesmo do cn_fast_hash do Monero/Nerva)."""
    r = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
         [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    rc = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
          0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
          0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
          0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
          0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
          0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
          0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
          0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

    def f(state):
        for rnd in range(24):
            c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
                 ^ state[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol64(c[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] ^= d[x]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(
                        state[x + 5 * y], r[x][y])
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = (b[x + 5 * y]
                                        ^ ((~b[((x + 1) % 5) + 5 * y])
                                           & b[((x + 2) % 5) + 5 * y]))
            state[0] ^= rc[rnd]

    rate = 136
    state = [0] * 25
    padded = data + b"\x01"
    while len(padded) % rate != rate - 1:
        padded += b"\x00"
    padded += b"\x80"
    for off in range(0, len(padded), rate):
        blk = padded[off:off + rate]
        for i in range(rate):
            state[i // 8] ^= blk[i] << (8 * (i % 8))
        f(state)
    return b"".join((state[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
                    for i in range(4))


def _b58_decode(enc):
    """Base58 do Monero/Nerva (por blocos de 8 bytes). Levanta ValueError."""
    full = _B58_FULL_ENC
    out = bytearray()
    for i in range(len(enc) // full):
        out += _b58_decode_bloco(enc[i * full:(i + 1) * full])
    resto = enc[len(enc) // full * full:]
    if resto:
        out += _b58_decode_bloco(resto)
    return bytes(out)


def _b58_decode_bloco(bloco):
    size = len(bloco)
    res_size = 0
    for i, es in enumerate(_B58_ENC_SIZES):
        if es == size:
            res_size = i
            break
    if res_size == 0:
        return b""
    n = 0
    ordem = 1
    for ch in reversed(bloco):
        dig = _B58_REV.get(ch)
        if dig is None:
            raise ValueError(f"símbolo base58 inválido: {ch!r}")
        n += ordem * dig
        ordem *= 58
    if res_size < _B58_FULL and (1 << (8 * res_size)) <= n:
        raise ValueError("bloco estoura os bytes permitidos")
    return n.to_bytes(res_size, "big")


def _varint_decode(data):
    n = 0
    shift = 0
    for i, b in enumerate(data):
        n |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return n, i + 1
    return n, len(data)


def validar_endereco_nerva(addr):
    """Valida um endereço Nerva mainnet. Retorna (válido, motivo)."""
    addr = addr.strip()
    try:
        raw = _b58_decode(addr)
    except (ValueError, IndexError) as e:
        return False, f"Erro no Base58: {e}"
    if len(raw) <= 4:
        return False, f"Tamanho curto demais ({len(raw)} bytes)"
    corpo = raw[:-4]
    checksum = raw[-4:]
    if _keccak256(corpo)[:4] != checksum:
        return False, "Checksum inválido"
    tag, lido = _varint_decode(corpo)
    if tag != 0x3800:  # prefixo mainnet do Nerva
        return False, (f"Prefixo {tag} — não é um endereço mainnet "
                       "(deve começar com 'NV')")
    if len(corpo) - lido != 64:
        return False, f"Chaves com tamanho errado ({len(corpo) - lido} bytes)"
    return True, "OK"


# ---------------------------------------------------------------------------
# Geração de carteira Nerva a partir da spend key (ed25519 puro, sem libs)
# Curva twisted Edwards: -x² + y² = 1 + d·x²·y²  (a = -1, d = -121665/121666)
# Endereço = varint(0x3800) + spend_pub(32) + view_pub(32) + keccak256[:4]
# ---------------------------------------------------------------------------
_P25519 = 2**255 - 19
_L25519 = 2**252 + 27742317777372353535851937790883648493
_D25519 = -121665 * pow(121666, -1, _P25519) % _P25519
_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_GY = 46316835694926478169428394003475163141307993866256225615783033603165251855960


def _ed_add(p, q):
    """Adição ed25519 em coordenadas afins (dois denominadores distintos!)."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    prod = x1 * x2 * y1 * y2 % _P25519
    den_x = (1 + _D25519 * prod) % _P25519   # x usa +
    den_y = (1 - _D25519 * prod) % _P25519   # y usa -
    num_x = (x1 * y2 + y1 * x2) % _P25519
    num_y = (y1 * y2 + x1 * x2) % _P25519    # a = -1  =>  y1*y2 + x1*x2
    return (num_x * pow(den_x, _P25519 - 2, _P25519) % _P25519,
            num_y * pow(den_y, _P25519 - 2, _P25519) % _P25519)


def _ed_mul(k, pt):
    """Multiplicação escalar (double-and-add)."""
    k %= _L25519
    r = None
    while k:
        if k & 1:
            r = _ed_add(r, pt)
        pt = _ed_add(pt, pt)
        k >>= 1
    return r


def _ponto_para_bytes(pt):
    """Compressão ed25519: y little-endian + bit de sinal de x no topo."""
    if pt is None:
        return b"\x01" + b"\x00" * 31
    x, y = pt
    b = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        b[31] |= 0x80
    return bytes(b)


def _sc_reduce32(s):
    """sc_reduce32 do Monero: 32 bytes little-endian módulo L."""
    return (int.from_bytes(s, "little") % _L25519).to_bytes(32, "little")


def _b58_encode(data):
    """Base58 do Monero/Nerva: blocos de 8 bytes -> 11 chars."""
    saida = []
    i = 0
    while i + _B58_FULL <= len(data):
        bloco = data[i:i + _B58_FULL]
        n = int.from_bytes(bloco, "big")
        tmp = []
        while n:
            n, r = divmod(n, 58)
            tmp.append(_ALPHABET58[r])
        tamanho = _B58_ENC_SIZES[_B58_FULL]
        tmp_s = "".join(reversed(tmp))
        saida.append("1" * (tamanho - len(tmp_s)) + tmp_s)
        i += _B58_FULL
    resto = data[i:]
    if resto:
        tamanho = (_B58_ENC_SIZES[len(resto)]
                   if len(resto) < len(_B58_ENC_SIZES) else 0)
        n = int.from_bytes(resto, "big")
        tmp = []
        while n:
            n, r = divmod(n, 58)
            tmp.append(_ALPHABET58[r])
        tmp_s = "".join(reversed(tmp))
        saida.append("1" * (tamanho - len(tmp_s)) + tmp_s)
    return "".join(saida)


def _varint_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def gerar_endereco_nerva(spend_hex):
    """Gera (endereço, spend_priv, view_priv, spend_pub, view_pub) em hex.
    `spend_hex` = spend key com 64 caracteres hex (ou 32 bytes raw)."""
    spend = bytes.fromhex(spend_hex)
    if len(spend) != 32:
        raise ValueError("spend key precisa de 32 bytes (64 hex)")
    a_priv = _sc_reduce32(spend)                     # spend priv reduzida
    v_priv = _sc_reduce32(_keccak256(a_priv))        # view priv derivada
    a_pub = _ponto_para_bytes(_ed_mul(
        int.from_bytes(a_priv, "little"), (_GX, _GY)))
    v_pub = _ponto_para_bytes(_ed_mul(
        int.from_bytes(v_priv, "little"), (_GX, _GY)))
    corpo = _varint_encode(0x3800) + a_pub + v_pub
    addr = _b58_encode(corpo + _keccak256(corpo)[:4])
    return addr, a_priv.hex(), v_priv.hex(), a_pub.hex(), v_pub.hex()


def gerar_carteira_nerva():
    """Assistente interativo: recebe a private key (hex ou inteiro) e gera
    a carteira Nerva real. Retorna o endereço (str)."""
    print("\n=====================================================")
    print("  GERAÇÃO DE CARTEIRA NERVA (XNV)")
    print("  A partir da sua spend/private key — gera o endereço real.")
    print("=====================================================")
    print("\nVocê pode colar a private key de duas formas:")
    print("  • HEX     : 0-9, a-f (ex.: 0000000000000000000000000000000000000000000000000000000000000001)")
    print("  • INTEIRO : número decimal grande (ex.: 12345678901234567890...)")
    print("  Qualquer valor é ajustado com zeros à esquerda até 64 chars,")
    print("  então o inteiro 1 vira 0000...0001 (igual ao hex 0000...0001).")
    print("  (a chave é tratada como escalar ed25519 e reduzida mod L)")
    print("  Deixe em branco para VOLTAR sem gerar.\n")

    while True:
        chave = perguntar("Private key (spend key)").strip()
        if not chave:
            return None
        try:
            def _normaliza_hex(h):
                """Ajusta zeros à esquerda até 64 chars (32 bytes).
                Comprimento ímpar ganha um '0' na frente para fromhex aceitar.
                Mais de 64 chars não cabe em 32 bytes -> erro."""
                if len(h) > 64:
                    raise ValueError("hex longo demais")
                if len(h) % 2 == 1:
                    h = "0" + h
                return bytes.fromhex(h.zfill(64))

            if chave.lower().startswith("0x"):
                spend = _normaliza_hex(chave[2:])
            elif any(c in "abcdefABCDEF" for c in chave):
                spend = _normaliza_hex(chave)
            else:
                # Só números (qualquer tamanho): sempre pergunta HEX x INTEIRO
                modo = perguntar(
                    f"'{chave}' é só número — interpretar como HEX (h) ou INTEIRO (i)?",
                    "h")
                if modo.strip().lower().startswith("i"):
                    n = int(chave)
                    if n.bit_length() > 256:
                        raise OverflowError("inteiro não cabe em 32 bytes")
                    spend = n.to_bytes(32, "big")   # zeros à esquerda: 1 -> 00...01
                else:
                    spend = _normaliza_hex(chave)   # zeros à esquerda
        except (ValueError, OverflowError):
            print("  [erro] Não consegui ler essa chave. Use HEX (64 chars), um")
            print("         inteiro decimal ou um hex menor (o valor cabe em 32 bytes).\n")
            continue
        if len(spend) != 32:
            print("  [erro] A chave gerou um tamanho inválido.\n")
            continue
        break

    try:
        addr, a_priv, v_priv, a_pub, v_pub = gerar_endereco_nerva(spend.hex())
    except ValueError as e:
        print(f"  [erro] {e}")
        return None

    print("\n-----------------------------------------------------")
    print("  CARTEIRA NERVA GERADA")
    print("-----------------------------------------------------")
    print(f"  Endereço (address):\n    {addr}")
    print(f"  Spend privada (hex):\n    {a_priv}")
    if a_priv != spend.hex():
        print(f"  [aviso] Spend key original ≥ L (ordem da curva ed25519).")
        print(f"          Reduzida mod L para o valor acima. O valor original")
        print(f"          não seria aceito pelo wallet oficial (sc_check).")
    print(f"  View privada  (hex):\n    {v_priv}")
    print(f"  Spend pública (hex):\n    {a_pub}")
    print(f"  View pública  (hex):\n    {v_pub}")
    print("-----------------------------------------------------")
    print("  Guarde as chaves privadas em lugar SEGURO. Quem tiver")
    print("  a spend privada controla seus fundos.")
    print("-----------------------------------------------------")

    if perguntar_sn("Usar este endereço na mineração?", "s"):
        return addr, a_priv, v_priv
    return None


def perguntar_endereco_nerva(cfg):
    """Pede o endereço Nerva e valida de verdade antes de aceitar.
    Digite 'g' para gerar uma carteira real a partir da private key.
    As chaves privadas são salvas em cfg para permitir consulta de saldo."""
    print("\n  Pode gerar uma carteira real agora digitando 'g' abaixo,")
    print("  ou cole o endereço que já tem (começa com 'NV').")
    print("  (as chaves privadas serão salvas na config se geradas)")
    while True:
        addr = perguntar(
            "Endereço da carteira Nerva (XNV) — a recompensa dos blocos cairá aqui"
            " ['g' para gerar]")
        if addr.strip().lower() in ("g", "gerar"):
            res = gerar_carteira_nerva()
            if res:
                addr, sk, vk = res
                cfg["nerva_spend_key"] = sk
                cfg["nerva_view_key"] = vk
                return addr
            continue
        ok, motivo = validar_endereco_nerva(addr)
        if ok:
            return addr
        print(f"\n  [erro] Endereço inválido — {motivo}.")
        print("         Endereços mainnet da Nerva começam com 'NV' e têm ~97 caracteres.")
        print("         Digite 'g' para gerar uma carteira real a partir da sua")
        print("         private key, ou use o NervaOne (https://nerva.one).\n")
        if not perguntar_sn("Usar mesmo assim (pode falhar na mineração)?", "n"):
            print("\n[OK] Nada foi salvo. Rode o script de novo com o endereço certo.")
            sys.exit(0)


def carregar_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            base = config_padrao()
            base.update({k: v for k, v in cfg.items() if k in base})
            return base
        except (ValueError, OSError) as e:
            print(f"[minerar.py] Config inválida ({CONFIG_FILE}): {e}")
            print("[minerar.py] Rode `python minerar.py --setup` para refazer.\n")
            sys.exit(1)
    return None


def salvar_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
        return True
    except OSError as e:
        print(f"[minerar.py] Não foi possível salvar a config: {e}", file=sys.stderr)
        return False


def configurar(coin_fixa=None):
    """Coleta as informações necessárias para minerar e salva a config.
    `coin_fixa` pula a pergunta da moeda (usado por --nerva)."""
    cfg = config_padrao()
    cores = os.cpu_count() or 2

    print("\n=====================================================")
    print("  CONFIGURAÇÃO DA MINERAÇÃO (uma vez só)")
    print("  Tudo que você digitar será salvo em minerar.config.json")
    print("=====================================================")
    print("  Produto do CanalQB — https://canalqb.com.br")
    print("=====================================================")
    print("\nEste minerador suporta SOMENTE o algoritmo CryptoNight")
    print("e pools com protocolo JSON-RPC 2.0 (estilo nodejs-pool).")
    print("Pools modernas de Monero usam RandomX e NÃO funcionam aqui.\n")

    # 1) Qual moeda será minerada
    cfg["coin"] = coin_fixa if coin_fixa else escolher_moeda()

    if "Monero" in cfg["coin"]:
        print("\n[aviso] Monero hoje usa RandomX (XMRig). Este minerador serve")
        print("        para versões ANTIGAS / forks pré-RandomX do CryptoNight.")
        print("        Certifique-se de que a pool fala JSON-RPC 2.0.\n")

    # Aviso para moedas com atividade incerta (nome ou nota podem conter o texto)
    for moeda_nome, nota, _ in MOEDAS:
        if moeda_nome == cfg["coin"] and ("atividade incerta" in nota or "atividade incerta" in moeda_nome):
            print("[aviso] Esta moeda pode não ter pools ativas ou pode estar")
            print("        descontinuada. Verifique se ainda há pools minerando-a")
            print("        antes de investir tempo.\n")
            if not perguntar_sn("Deseja continuar mesmo assim?", "n"):
                print("\n[OK] Nada foi salvo. Rode o script de novo para escolher outra moeda.")
                sys.exit(0)

    # 1b) Saldo mínimo para receber pagamento (pool ou exchange)
    cfg["payout_min"] = perguntar(
        "Saldo mínimo para receber o pagamento — pool ou exchange (ex.: 40 XNV)",
        sugestao_payout(cfg["coin"]))

    # Nerva (XNV) = mineração SOLO com o daemon oficial (nervad). Não existe
    # pool e o minerd NÃO roda XNV — então pede só o essencial e pula os
    # campos de pool (url, worker, pass, etc.).
    if "Nerva" in cfg["coin"]:
        print("\n[aviso] Nerva (XNV) é mineração SOLO — não existe pool. O script")
        print("        usa o daemon oficial nervad.exe (CryptoNight-Adaptive v6).")
        print("        Baixe o pacote em https://nerva.one/#downloads se pedir.\n")
        cfg["address"] = perguntar_endereco_nerva(cfg)
        cfg["nerva_threads"] = perguntar_int(
            f"Quantas threads de CPU para minerar? (sua máquina tem {cores} núcleos)",
            max(1, cores - 1), minimo=1, maximo=cores)
        cfg["nerva_affinity"] = perguntar_sn(
            "Fixar threads nos núcleos físicos? (recomendado)", "s")
        cfg["nerva_bg"] = perguntar_sn(
            "Mineração só em segundo plano (quando o PC está ocioso)?", "n")
        if not salvar_config(cfg):
            sys.exit(1)
        print(f"\n[OK] Configuração salva em: {CONFIG_FILE}\n")
        print("[OK] Na primeira execução o nervad baixa a blockchain — pode")
        print("     demorar alguns minutos. Depois disso, inicia rápido.\n")
        return cfg

    # 2) Endereço da carteira (com validação por moeda)
    cfg["address"] = perguntar(
        f"Endereço da carteira ({cfg['coin']}) — a moeda minerada cairá aqui")
    validar_address(cfg["address"], cfg["coin"])

    cfg["worker"] = perguntar(
        "Nome do worker (apelido da sua máquina no pool)", "worker")
    cfg["url"] = perguntar(
        "URL do pool (ex.: stratum+tcp://pool.exemplo.com:3333)")

    cfg["pass"] = perguntar("Senha do pool", DEFAULT_PASS)
    cfg["threads"] = perguntar_int(
        f"Quantas threads de CPU? (sua máquina tem {cores} núcleos)",
        cfg["threads"], minimo=1, maximo=cores * 2)
    cfg["priority"] = perguntar_int(
        "Prioridade (19 = cede CPU, 0 = normal, -20 = máxima)", 19,
        minimo=-20, maximo=19)
    cfg["throttle"] = perguntar_int(
        "Throttle em µs (0 = máximo, 2000+ = menos calor/consumo)", 0,
        minimo=0)
    cfg["no_affinity"] = perguntar_sn(
        "Desativar fixação das threads aos núcleos? (recomendado: não)", "n")
    cfg["quiet"] = perguntar_sn(
        "Rodar em modo silencioso (sem hashmeter por thread)?", "n")
    cfg["debug"] = perguntar_sn("Logs de debug?", "n")

    if not salvar_config(cfg):
        sys.exit(1)

    print(f"\n[OK] Configuração salva em: {CONFIG_FILE}\n")
    return cfg


def mostrar_config(cfg):
    print("\nConfiguração salva em", CONFIG_FILE)
    print("-" * 50)
    for chave, valor in cfg.items():
        print(f"  {chave:12s}: {valor}")
    print("-" * 50)


# ---------------------------------------------------------------------------
# Binário e comando
# ---------------------------------------------------------------------------

def localizar_binario():
    if platform.system() == "Windows":
        nomes = [BIN_WIN, BIN_LINUX]
    else:
        nomes = [BIN_LINUX, BIN_WIN]
    for nome in nomes:
        caminho = os.path.join(PROJETO_DIR, nome)
        if os.path.isfile(caminho):
            return caminho
        no_path = shutil.which(nome)
        if no_path:
            return no_path
    return None


def instrucoes_build():
    if platform.system() == "Windows":
        return (
            "\nO binário ainda não foi compilado. No Windows, instale o MSYS2 "
            "(https://www.msys2.org/) e, no terminal MINGW64, rode:\n\n"
            "    pacman -S --needed base-devel mingw-w64-x86_64-toolchain "
            "mingw-w64-x86_64-curl git autoconf automake libtool\n"
            "    cd " + PROJETO_DIR + "\n"
            "    ./autogen.sh\n"
            "    CFLAGS=\"-O3\" ./configure\n"
            "    make\n\n"
            "Depois rode este script novamente."
        )
    return (
        "\nO binário ainda não foi compilado. No Linux (Debian/Ubuntu):\n\n"
        "    sudo apt install -y build-essential autoconf automake libtool "
        "pkg-config libcurl4-openssl-dev git\n"
        "    cd " + PROJETO_DIR + "\n"
        "    ./autogen.sh\n"
        "    CFLAGS=\"-march=native\" ./configure\n"
        "    make -j\"$(nproc)\"\n\n"
        "Depois rode este script novamente."
    )


def localizar_nervad():
    """Procura o daemon oficial da Nerva (nervad.exe) que faz mineração SOLO."""
    # 1) Pasta do projeto
    p = os.path.join(PROJETO_DIR, NERVA_BIN_WIN)
    if os.path.isfile(p):
        return p
    # 2) PATH
    no_path = shutil.which(NERVA_BIN_WIN)
    if no_path:
        return no_path
    # 3) Pastas irmãs começando com 'nerva-'
    raiz = os.path.dirname(PROJETO_DIR)
    try:
        for nome in sorted(os.listdir(raiz)):
            if nome.startswith("nerva-") and os.path.isdir(os.path.join(raiz, nome)):
                p = os.path.join(raiz, nome, NERVA_BIN_WIN)
                if os.path.isfile(p):
                    return p
    except OSError:
        pass
    return None


def localizar_nerva_wallet_rpc():
    """Procura o nerva-wallet-rpc.exe (consulta de saldo)."""
    nome = "nerva-wallet-rpc.exe"
    # 1) Pasta do projeto
    p = os.path.join(PROJETO_DIR, nome)
    if os.path.isfile(p):
        return p
    # 2) PATH
    no_path = shutil.which(nome)
    if no_path:
        return no_path
    # 3) Pastas irmãs começando com 'nerva-'
    raiz = os.path.dirname(PROJETO_DIR)
    try:
        for nome_dir in sorted(os.listdir(raiz)):
            if nome_dir.startswith("nerva-") and os.path.isdir(os.path.join(raiz, nome_dir)):
                p = os.path.join(raiz, nome_dir, nome)
                if os.path.isfile(p):
                    return p
    except OSError:
        pass
    return None


def instrucoes_nerva():
    return (
        "\nO daemon oficial da Nerva (nervad.exe) não foi encontrado.\n\n"
        "Baixe o pacote Windows em https://nerva.one/#downloads (v0.3.0.0\n"
        "ou mais novo) e extraia junto deste projeto, ou apenas copie o\n"
        "arquivo nervad.exe para a pasta:\n\n    " + PROJETO_DIR + "\n\n"
        "Depois rode este script novamente."
    )


def montar_comando(binario, cfg, args):
    cmd = [binario]

    if args.benchmark:
        cmd += ["--benchmark", "--threads", str(args.threads or cfg.get("threads", 1))]
        if args.priority is not None:
            cmd += ["--priority", str(args.priority)]
        if args.extra:
            cmd += args.extra
        return cmd

    user = f"{cfg['address']}.{cfg['worker']}" if cfg.get("worker") else cfg["address"]
    cmd += ["--url", cfg["url"], "--user", user, "--pass", cfg["pass"]]
    cmd += ["--threads", str(args.threads if args.threads is not None else cfg["threads"])]
    cmd += ["--priority", str(args.priority if args.priority is not None else cfg["priority"])]

    throttle = args.throttle if args.throttle is not None else cfg.get("throttle", 0)
    if throttle:
        cmd += ["--throttle", str(throttle)]

    if args.no_affinity or cfg.get("no_affinity"):
        cmd.append("--no-affinity")
    if args.quiet or cfg.get("quiet"):
        cmd.append("--quiet")
    if args.debug or cfg.get("debug"):
        cmd.append("--debug")
    if args.extra:
        cmd += args.extra
    return cmd


def args_sync_nerva():
    """Flags que aceleram a sincronização inicial do nervad: mais peers de
    saída (download paralelo), limite de download mais alto e mais threads
    para preparar blocos (CPU-bound durante o fast-block-sync)."""
    ncores = os.cpu_count() or 4
    prep = max(4, min(8, ncores))
    return ["--out-peers", "16",
            "--limit-rate-down", "32768",   # 32 MB/s (default é 8 MB/s)
            "--prep-blocks-threads", str(prep)]


def montar_comando_nerva(binario, cfg, args):
    """Comando para o daemon oficial Nerva: sync + mineração solo (sem pool)."""
    threads = args.threads if args.threads is not None else cfg.get("nerva_threads", 1)
    cmd = [binario,
           "--data-dir", NERVA_DATA_DIR,
           "--no-analytics",
           "--log-level", "1",
           "--start-mining", cfg["address"],
           "--mining-threads", str(threads)]
    cmd += args_sync_nerva()
    # Contorna falha do DNS-over-TCP do daemon em algumas redes
    for seed in NERVA_SEED_PEERS:
        cmd += ["--add-peer", seed]
    if cfg.get("nerva_affinity", True) and not getattr(args, "no_affinity", False):
        cmd.append("--mining-affinity")
    if cfg.get("nerva_bg", False):
        cmd.append("--bg-mining-enable")
    return cmd


# Processo do daemon Nerva de fundo iniciado por este script (sync em background).
# Ele vive enquanto o script vive; ao minerar em foreground é encerrado para
# liberar as portas (o nervad só inicia a mineração via --start-mining no comando).
DAEMON_NERVA_PROC = None


def garantir_daemon_nerva(avisar=True):
    """Garante que o nervad está rodando em segundo plano (só sync) enquanto
    o script carrega. Se já houver um daemon respondendo na porta, apenas usa.
    Retorna True se o RPC está de pé (daemon pronto)."""
    global DAEMON_NERVA_PROC
    if consultar_rpc("get_info"):
        return True
    binario = localizar_nervad()
    if not binario:
        return False
    if avisar:
        print("\n  Carregando o daemon Nerva (nervad) em segundo plano...")
    cmd = [binario,
           "--data-dir", NERVA_DATA_DIR,
           "--no-analytics",
           "--log-level", "0"]
    cmd += args_sync_nerva()
    for seed in NERVA_SEED_PEERS:
        cmd += ["--add-peer", seed]
    try:
        DAEMON_NERVA_PROC = subprocess.Popen(
            cmd, stdin=subprocess.PIPE,  # stdin aberto evita fecho no Windows
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"  [erro] Falha ao iniciar nervad: {e}")
        return False
    for _ in range(20):  # até ~60s
        if DAEMON_NERVA_PROC.poll() is not None:
            print("  [erro] nervad encerrou antes de ficar pronto.")
            DAEMON_NERVA_PROC = None
            return False
        if consultar_rpc("get_info"):
            return True
        time.sleep(3)
    print("  [erro] nervad não ficou pronto dentro do tempo limite.")
    DAEMON_NERVA_PROC = None
    return False


def parar_daemon_nerva_fundo():
    """Encerra o daemon de fundo iniciado por este script (se houver), para
    liberar as portas antes de iniciar a mineração em foreground.
    No Windows usa taskkill //F (mais confiável que terminate()) e aguarda
    a porta RPC ficar inacessível (até 5s) antes de retornar."""
    global DAEMON_NERVA_PROC
    proc = DAEMON_NERVA_PROC
    DAEMON_NERVA_PROC = None
    if not proc or proc.poll() is not None:
        return
    pid = proc.pid
    # 1) taskkill //F (força kill no Windows)
    try:
        subprocess.run(["taskkill", "//F", "//PID", str(pid)],
                       capture_output=True, timeout=10)
    except Exception:
        pass
    # 2) fallback: terminate() caso taskkill não tenha funcionado
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    # 3) Aguarda a porta RPC ser liberada (máx 5s)
    for _ in range(5):
        if not consultar_rpc("get_info"):
            break
        time.sleep(1)


# Processo do nerva-wallet-rpc de fundo (consulta de saldo em 2º plano).
# Vive enquanto o script vive; é encerrado na saída junto com o daemon.
WALLET_RPC_PROC = None
WALLET_RPC_TMPDIR = None


def parar_wallet_rpc_fundo():
    """Encerra o nerva-wallet-rpc de fundo (se houver) e remove a pasta
    temporária da carteira. No Windows usa taskkill //F (mais confiável)."""
    global WALLET_RPC_PROC, WALLET_RPC_TMPDIR
    proc = WALLET_RPC_PROC
    WALLET_RPC_PROC = None
    if proc and proc.poll() is None:
        try:
            subprocess.run(["taskkill", "//F", "//PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
    if WALLET_RPC_TMPDIR:
        tmp = WALLET_RPC_TMPDIR
        WALLET_RPC_TMPDIR = None
        shutil.rmtree(tmp, ignore_errors=True)


# Limpeza global na saída do script: encerra o daemon de fundo
# se ainda estiver rodando, evitando que sobreviva como órfão.
atexit.register(parar_daemon_nerva_fundo)
atexit.register(parar_wallet_rpc_fundo)


def executar(binario, cmd, stats=None):
    print(f"[minerar.py] Binário : {binario}")
    print(f"[minerar.py] Comando : {' '.join(cmd)}")
    print("[minerar.py] Pressione Ctrl+C para encerrar.\n")

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=PROJETO_DIR,
            stdin=subprocess.PIPE,  # mantém aberto p/ nervad não ler EOF
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as e:
        print(f"[minerar.py] Falha ao executar o binário: {e}", file=sys.stderr)
        return 1

    def encerrar(_sig=None, _frame=None):
        print("\n[minerar.py] Encerrando minerador...")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise SystemExit(proc.returncode)

    try:
        signal.signal(signal.SIGINT, encerrar)
    except ValueError:
        pass  # fora da thread principal

    # Flag para saber se a linha anterior foi do tipo "Synced" —
    # nesse caso, antes de escrever uma linha normal, quebra a linha
    # para não colar no final do \r.
    _ultima_foi_sync = False
    try:
        for linha in proc.stdout:
            # Linhas de sincronização do nervad ("Synced X/Y (Z%, W left)")
            # são exibidas na mesma linha com \r, em vez de uma linha nova
            # a cada segundo — evita poluir o terminal.
            eh_sync = " Synced " in linha and "/" in linha and "left)" in linha
            if eh_sync:
                # Extrai só a parte útil (ex.: "Synced 918373/4376286 (20%, 3457913 left)")
                m = re.search(r"Synced \d+/\d+ \(\d+%, \d+ left\)", linha)
                texto = m.group(0) if m else linha.strip()
                sys.stdout.write(f"\r  {texto}  ")
                _ultima_foi_sync = True
            else:
                if _ultima_foi_sync:
                    sys.stdout.write("\n")  # quebra a linha do \r anterior
                    _ultima_foi_sync = False
                sys.stdout.write(linha)
            sys.stdout.flush()
            if stats is not None:
                parsear_linha_minerd(linha, stats)
    except KeyboardInterrupt:
        if _ultima_foi_sync:
            sys.stdout.write("\n")
        encerrar()

    proc.wait()
    print(f"\n[minerar.py] Minerador encerrado (código {proc.returncode}).")
    return proc.returncode


# ---------------------------------------------------------------------------
# Dashboard local (painel web ao vivo — http://localhost:8080)
# ---------------------------------------------------------------------------

DASHBOARD_PADRAO = 8080

PAGINA_HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>minerar.py — CanalQB</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         background: #0f1420; color: #e8eef7; margin: 0; padding: 24px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: #8fa1bd; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
  .card { background: #1a2233; border: 1px solid #2a3550; border-radius: 10px; padding: 14px 16px; }
  .card .label { color: #8fa1bd; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  .card .valor { font-size: 22px; font-weight: 600; margin-top: 6px; word-break: break-all; }
  footer { margin-top: 24px; color: #5d6d88; font-size: 13px; text-align: center; }
  footer a { color: #7aa2f7; }
</style>
</head>
<body>
  <h1>minerar.py — CanalQB</h1>
  <div class="sub">Painel ao vivo do CPUMiner-Multi</div>
  <div class="grid">
    <div class="card"><div class="label">Moeda</div><div class="valor" id="coin">—</div></div>
    <div class="card"><div class="label">Hashrate</div><div class="valor" id="hashrate">—</div></div>
    <div class="card"><div class="label">Aceitas</div><div class="valor" id="accepted">—</div></div>
    <div class="card"><div class="label">Rejeitadas</div><div class="valor" id="rejected">—</div></div>
    <div class="card"><div class="label">Aproveitamento</div><div class="valor" id="aceite_pct">—</div></div>
    <div class="card"><div class="label">Uptime</div><div class="valor" id="uptime">—</div></div>
    <div class="card"><div class="label">Pool</div><div class="valor" id="pool">—</div></div>
    <div class="card"><div class="label">Saldo mín. pagamento</div><div class="valor" id="payout_min">—</div></div>
    <div class="card"><div class="label">Endereço</div><div class="valor" id="address">—</div></div>
    <div class="card"><div class="label">Worker</div><div class="valor" id="worker">—</div></div>
    <div class="card"><div class="label">Algoritmo</div><div class="valor" id="algo">—</div></div>
    <div class="card"><div class="label">Threads</div><div class="valor" id="threads">—</div></div>
    <div class="card"><div class="label">Altura (bloco)</div><div class="valor" id="height">—</div></div>
    <div class="card"><div class="label">Dificuldade</div><div class="valor" id="difficulty">—</div></div>
    <div class="card"><div class="label">Sincronizado</div><div class="valor" id="synced">—</div></div>
  </div>
  <footer>Produto do CanalQB — <a href="https://canalqb.com.br">canalqb.com.br</a></footer>
<script>
async function atualizar() {
  try {
    const r = await fetch('/stats');
    const s = await r.json();
    const campos = ['coin','hashrate','accepted','rejected','aceite_pct','uptime',
                    'pool','payout_min','address','worker','algo','threads',
                    'height','difficulty','synced'];
    for (const k of campos) {
      const el = document.getElementById(k);
      if (el && s[k] !== undefined && s[k] !== null && s[k] !== '') el.textContent = s[k];
    }
  } catch (e) { /* dashboard ainda iniciando */ }
}
setInterval(atualizar, 2000);
atualizar();
</script>
</body>
</html>
"""


def parsear_linha_minerd(linha, stats):
    """Atualiza o dict `stats` com o que o minerd imprime no terminal."""
    m = re.search(r"accepted:\s*(\d+)/(\d+)\s*\(([\d.]+)%\),\s*([\d.]+)\s*H/s", linha)
    if m:
        aceitas, total, pct, hs = m.groups()
        stats["accepted"] = int(aceitas)
        stats["rejected"] = int(total) - int(aceitas)
        stats["aceite_pct"] = pct + "%"
        stats["hashrate"] = float(hs)
        return
    m = re.search(r"Total:\s*([\d.]+)\s*H/s", linha)
    if m:
        stats["hashrate"] = float(m.group(1))
        return
    m = re.search(r"Starting Stratum on (\S+)", linha)
    if m:
        stats["pool"] = m.group(1)
        return
    m = re.search(r"(\d+) miner threads started, using '([^']+)' algorithm", linha)
    if m:
        stats["threads"] = int(m.group(1))
        stats["algo"] = m.group(2)


def criar_stats(cfg):
    """Monta o dict de estatísticas compartilhado (dashboard + terminal)."""
    def horario(v):
        return v if v else "—"

    stats = {
        "coin": horario(cfg.get("coin")),
        "address": horario(cfg.get("address")),
        "worker": horario(cfg.get("worker")),
        "pool": "—",
        "algo": "—",
        "threads": horario(cfg.get("threads")),
        "payout_min": horario(cfg.get("payout_min")),
        "hashrate": 0.0,
        "accepted": 0,
        "rejected": 0,
        "aceite_pct": "—",
        "height": "—",
        "target_height": "—",
        "difficulty": "—",
        "synced": "—",
        "inicio": time.time(),
    }
    if "Nerva" in str(cfg.get("coin", "")):
        stats["algo"] = "CryptoNight-Adaptive v6 (solo)"
        stats["pool"] = "SOLO — sem pool"
        stats["threads"] = horario(cfg.get("nerva_threads"))
    return stats


def consultar_rpc(metodo, porta=NERVA_RPC_PORT):
    """Chama um método JSON-RPC do daemon Nerva (http://127.0.0.1:porta)."""
    corpo = json.dumps({"jsonrpc": "2.0", "id": "0", "method": metodo}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{porta}/json_rpc", data=corpo,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            dados = json.load(r)
            return dados.get("result") or {}
    except Exception:
        return {}


def consultar_saldo_nerva(cfg, em_segundo_plano=False):
    """Consulta o saldo de uma carteira Nerva usando o nerva-wallet-rpc.

    A Nerva é uma moeda de privacidade: o saldo NÃO pode ser obtido pelo
    endereço público — é preciso importar a spend/view key. Para isso o
    script usa o nerva-wallet-rpc (mesmo pacote do nervad) conectado ao
    daemon local, gera a carteira a partir das chaves salvas na config e
    lê o get_balance. Retorna True em sucesso.

    Com em_segundo_plano=True o wallet-rpc fica vivo em background (numa
    thread daemon) e a função retorna na hora: o % de sincronização é
    impresso e o saldo aparece no terminal quando a carteira chega a 100%.
    Nesse modo o daemon e o wallet-rpc NÃO são encerrados aqui — seguem
    vivos para a mineração e são limpos na saída do script."""
    if not cfg.get("nerva_spend_key") or not cfg.get("nerva_view_key"):
        print("\n  [aviso] Para consultar o saldo, a config precisa ter as chaves")
        print("          privadas (spend/view). Gere uma carteira com:")
        print("          python minerar.py --gerar-carteira")
        return False

    binario = localizar_nerva_wallet_rpc()
    if not binario:
        print("\n  [aviso] nerva-wallet-rpc.exe não encontrado. Baixe o pacote")
        print("          oficial em https://nerva.one/#downloads (vem junto do nervad).")
        return False

    # O daemon precisa estar de pé para o wallet-rpc sincronizar.
    # Reutiliza o daemon de fundo deste script (se houver) ou sobe um
    # temporário (sem --start-mining) apenas para a consulta.
    if not consultar_rpc("get_info"):
        # Se já há um daemon de fundo deste script vivo mas com RPC ainda
        # não respondendo (ex.: ocupado com sync), aguarda um pouco mais
        # antes de concluir que ele caiu — evita subir um segundo daemon.
        if DAEMON_NERVA_PROC is not None and DAEMON_NERVA_PROC.poll() is None:
            for _ in range(10):  # até ~20s
                if consultar_rpc("get_info"):
                    break
                time.sleep(2)
        if not consultar_rpc("get_info"):
            # Daemon de fundo caiu (ou nunca subiu): encerra resto e sobe novo.
            parar_daemon_nerva_fundo()
            print("\n  Subindo o daemon Nerva em segundo plano para consultar o saldo...")
            if not garantir_daemon_nerva(avisar=False):
                print("  [erro] Não foi possível subir o daemon Nerva para consultar o saldo.")
                print("          Verifique se as portas 17565/17566 estão livres e tente de novo.")
                return False
            print("  Daemon pronto. Consultando saldo...")

    tmp_dir = tempfile.mkdtemp(prefix="nerva_saldo_", dir=PROJETO_DIR)
    cfg_json = {
        "version": 1,
        "filename": "carteira_saldo",
        "scan_from_height": 0,
        "password": "minerar",
        "viewkey": cfg["nerva_view_key"],
        "spendkey": cfg["nerva_spend_key"],
    }
    with open(os.path.join(tmp_dir, "carteira.json"), "w", encoding="utf-8") as f:
        json.dump(cfg_json, f)

    proc = subprocess.Popen(
        [binario,
         "--generate-from-json", os.path.join(tmp_dir, "carteira.json"),
         "--daemon-address", f"127.0.0.1:{NERVA_RPC_PORT}",
         "--rpc-bind-port", str(NERVA_WALLET_RPC_PORT),
         "--disable-rpc-login"],
        cwd=tmp_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    global WALLET_RPC_PROC, WALLET_RPC_TMPDIR
    WALLET_RPC_PROC = proc
    WALLET_RPC_TMPDIR = tmp_dir

    if em_segundo_plano:
        # Sincronização em segundo plano: thread daemon imprime o % e, ao
        # chegar a 100%, mostra o saldo. O proc é limpo na saída do script.
        print("\n  [minerar.py] Consulta de saldo em SEGUNDO PLANO — a carteira")
        print("               está sincronizando. O % de progresso é mostrado")
        print("               abaixo e o saldo aparece quando chegar a 100%.\n")
        threading.Thread(target=_esperar_saldo_nerva,
                         args=(proc, em_segundo_plano), daemon=True).start()
        return True

    try:
        return _esperar_saldo_nerva(proc, em_segundo_plano)
    finally:
        # Consulta única (--saldo): encerra o wallet-rpc e o daemon de fundo.
        parar_wallet_rpc_fundo()
        if DAEMON_NERVA_PROC is not None:
            print("\n  Encerrando o daemon de fundo...")
            parar_daemon_nerva_fundo()


def _esperar_saldo_nerva(proc, em_segundo_plano):
    """Aguarda a carteira sincronizar e mostra o saldo quando chegar a 100%.
    Imprime o % de progresso (altura atual vs alvo do daemon) enquanto isso.
    Retorna True ao exibir o saldo, False em erro. Em segundo plano roda
    como thread daemon e o retorno é ignorado."""
    def fmt(x):
        return f"{x / 1e12:,.8f} XNV"

    ultima_linha = ""
    while True:
        if proc.poll() is not None:
            print("\n  [erro] nerva-wallet-rpc encerrou antes de sincronizar.")
            return False

        # Progresso do daemon (altura atual vs alvo) — o % que o usuário vê
        info = consultar_rpc("get_info")
        prog = _progresso_nerva({
            "height": (info or {}).get("height", 0),
            "target_height": (info or {}).get("target_height", 0)})
        daemon_sync = bool(info and info.get("synchronized"))

        # Tenta ler o saldo — pode falhar/timeout enquanto a carteira escaneia
        saldo = desbloqueado = None
        corpo = json.dumps({
            "jsonrpc": "2.0", "id": "0",
            "method": "get_balance",
            "params": {"account_index": 0}}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{NERVA_WALLET_RPC_PORT}/json_rpc",
            data=corpo, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                res = json.load(r).get("result") or {}
                saldo = res.get("balance")
                desbloqueado = res.get("unlocked_balance")
        except Exception:
            pass

        # Só mostra o saldo quando o daemon estiver sincronizado E a carteira
        # tiver respondido (garante que o valor reflete a blockchain toda).
        if daemon_sync and saldo is not None:
            print("\n-----------------------------------------------------")
            print("  SALDO DA CARTEIRA NERVA (XNV)")
            print("-----------------------------------------------------")
            print(f"  Total:        {fmt(saldo)}")
            print(f"  Desbloqueado: {fmt(desbloqueado or 0)}")
            print("-----------------------------------------------------")
            print("  Lembrete: a Nerva exige saldo mínimo de 40 XNV por bloco")
            print("  para liberar o pagamento (mecanismo anti-dust).")
            print("-----------------------------------------------------")
            return True

        if prog is None:
            msg = "sincronizando… aguardando a rede"
        elif daemon_sync:
            msg = ("carteira escaneando o histórico… (daemon 100%) "
                   "— saldo aparecerá ao concluir")
        else:
            msg = (f"sincronizando… {prog:.1f}% "
                   f"({info.get('height', '—')}/{info.get('target_height', '—')}) "
                   f"— saldo aparece quando 100%")
        linha = f"[minerar.py] {msg}"
        if linha != ultima_linha:
            if em_segundo_plano:
                print(linha, flush=True)
            else:
                print("\r" + linha + " " * max(0, len(ultima_linha) - len(linha)),
                      end="", flush=True)
            ultima_linha = linha
        time.sleep(5)


def consultar_uri(uri, porta=NERVA_RPC_PORT):
    """Faz GET numa URI do RPC HTTP do nervad (ex.: /mining_status)."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{porta}{uri}",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.load(r)
    except Exception:
        return {}


def poller_nerva_rpc(stats, porta=NERVA_RPC_PORT):
    """Atualiza `stats` consultando o RPC do nervad (hashrate, altura, diff)."""
    while True:
        info = consultar_rpc("get_info", porta)
        if info:
            stats["height"] = info.get("height", "—")
            stats["target_height"] = info.get("target_height", "—")
            stats["difficulty"] = info.get("difficulty", "—")
            stats["synced"] = "sim" if info.get("synchronized") else "sincronizando…"
        # mining_status é uma URI direta, não JSON-RPC
        min_status = consultar_uri("/mining_status", porta)
        if min_status and min_status.get("status") == "OK":
            if min_status.get("active"):
                stats["hashrate"] = float(min_status.get("speed") or 0)
                tc = min_status.get("threads_count")
                if tc:
                    stats["threads"] = tc
            else:
                stats["hashrate"] = 0.0
        time.sleep(5)


def _progresso_nerva(stats):
    """Percentual de sincronização (0-100) a partir da altura atual vs alvo."""
    h = stats.get("height")
    t = stats.get("target_height")
    try:
        h, t = int(h), int(t)
    except (TypeError, ValueError):
        return None
    if t <= 0:
        return None
    return max(0.0, min(100.0, h * 100.0 / t))


def relogio_nerva(stats):
    """Imprime um resumo periódico no terminal (hashrate/altura da Nerva).
    A primeira linha sai logo (útil durante a sincronização inicial), depois
    a cada 60s."""
    primeiro = True
    while True:
        if not primeiro:
            time.sleep(60)
        primeiro = False
        hr = stats.get("hashrate") or 0
        prog = _progresso_nerva(stats)
        if stats.get("synced") == "sim":
            info_sync = "sincronizado"
        elif prog is not None:
            info_sync = (f"sincronizando… {prog:.1f}% "
                         f"({stats.get('height', '—')}/{stats.get('target_height', '—')})")
        else:
            info_sync = "sincronizando…"
        print(f"[minerar.py] XNV solo · {hr:.2f} H/s · altura {stats.get('height', '—')} · "
              f"diff {stats.get('difficulty', '—')} · {info_sync}", flush=True)


def iniciar_dashboard(cfg, porta=DASHBOARD_PADRAO):
    """Sobe um mini-servidor HTTP local com as estatísticas ao vivo.
    Retorna (stats, servidor) — ou (None, None) se a porta estiver ocupada."""
    stats = criar_stats(cfg)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/stats":
                dados = {k: stats[k] for k in stats if k != "inicio"}
                dados["uptime"] = int(time.time() - stats["inicio"])
                corpo = json.dumps(dados).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(corpo)))
                self.end_headers()
                self.wfile.write(corpo)
            else:
                corpo = PAGINA_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(corpo)))
                self.end_headers()
                self.wfile.write(corpo)

        def log_message(self, *args):
            pass  # silencia o log padrão do servidor

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", porta), Handler)
    except OSError:
        print(f"[minerar.py] Aviso: porta {porta} em uso — dashboard desativado neste run.")
        return None, None

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return stats, srv


def rodar_com_dashboard(binario, cfg, cmd, args):
    """Executa o minerador e, se `--dashboard` foi pedido, sobe o painel web.
    No modo Nerva (solo), também liga o RPC poller e o resumo de terminal."""
    eh_nerva = "Nerva" in str(cfg.get("coin", "")) or getattr(args, "nerva", False)
    if eh_nerva:
        # O daemon de fundo (sync) ocupa as portas RPC — encerra antes de
        # minerar em foreground para evitar conflito de porta.
        parar_daemon_nerva_fundo()

    stats, srv = None, None
    if args.dashboard:
        stats, srv = iniciar_dashboard(cfg, args.dashboard)
        if srv:
            print(f"[minerar.py] Dashboard: http://localhost:{args.dashboard}  (Ctrl+C para sair)")
    elif eh_nerva:
        stats = criar_stats(cfg)

    if eh_nerva and stats is not None:
        threading.Thread(target=poller_nerva_rpc, args=(stats,), daemon=True).start()
        threading.Thread(target=relogio_nerva, args=(stats,), daemon=True).start()

    try:
        return executar(binario, cmd, stats) or 0
    finally:
        if srv:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Evita crash de encoding (UnicodeEncodeError) em terminais com
    # codepage antiga (ex.: cmd com cp850/cp1252) ou saída redirecionada.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    cores = os.cpu_count() or 2

    parser = argparse.ArgumentParser(
        prog="minerar.py",
        description="Executa o CPUMiner-Multi do @CanalQb.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemplos:\n"
               "  python minerar.py                # 1ª vez configura; depois minera direto\n"
               "  python minerar.py --setup        # refazer a configuração\n"
               "  python minerar.py --show         # ver a config salva\n"
               "  python minerar.py --benchmark    # benchmark offline\n"
               "  python minerar.py --nerva        # minera Nerva solo com nervad.exe\n"
               "  python minerar.py --gerar-carteira 0100...0   # gera carteira Nerva da spend key\n"
               "  python minerar.py --saldo        # consulta o saldo da carteira Nerva salva\n"
               "  python minerar.py -t 2 --throttle 2000   # ajusta no run atual\n",
    )
    parser.add_argument(
        "-o", "--url", metavar="URL",
        help="URL da pool — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "-u", "--user", metavar="USER",
        help="Usuário (CARTEIRA.worker) — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "-p", "--pass", dest="passwd", metavar="PASS",
        help="Senha do pool — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "-t", "--threads", type=int, metavar="N",
        help="Número de threads — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "--priority", type=int, metavar="N",
        help="Prioridade nice (-20 a 19) — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "--throttle", type=int, metavar="N",
        help="Pausa em µs entre lotes — sobrescreve a config deste run.",
    )
    parser.add_argument(
        "--no-affinity", action="store_true",
        help="Desliga o pinning das threads aos núcleos (deste run).",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Desliga o hashmeter por thread (deste run).",
    )
    parser.add_argument(
        "-D", "--debug", action="store_true",
        help="Logs de debug do minerador (deste run).",
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Refazer a configuração do zero.",
    )
    parser.add_argument(
        "--show", action="store_true",
        help="Mostrar a config salva e sair.",
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Benchmark offline (ignora a config e a pool).",
    )
    parser.add_argument(
        "--dashboard", nargs="?", const=DASHBOARD_PADRAO, type=int, metavar="PORTA",
        help="Abre painel web local com hashrate/shares/pool ao vivo (padrão: porta 8080).",
    )
    parser.add_argument(
        "--nerva", action="store_true",
        help="Minera Nerva (XNV) solo com o daemon oficial nervad (sem pool, sem minerd).",
    )
    parser.add_argument(
        "--gerar-carteira", nargs="?", const="__interativo__", metavar="HEX",
        help="Gera a carteira Nerva a partir da spend key (hex ou inteiro). "
             "Sem argumento, pergunta a chave. Não minera.",
    )
    parser.add_argument(
        "--saldo", action="store_true",
        help="Consulta o saldo da carteira Nerva salva na config "
             "(precisa das chaves e do daemon sincronizado).",
    )
    parser.add_argument(
        "--extra", nargs=argparse.REMAINDER,
        help="Argumentos adicionais passados direto ao minerd (depois de --).",
    )
    args = parser.parse_args()

    # Nerva: assim que o script carrega, o daemon (nervad) sobe em segundo
    # plano para já ir sincronizando a blockchain — configuração, saldo,
    # geração de carteira e mineração passam a usar esse daemon. Antes de
    # minerar em foreground, ele é encerrado para liberar as portas.
    cfg_ini = carregar_config() or {}
    eh_nerva = (args.nerva or args.saldo or args.gerar_carteira
                or "Nerva" in str(cfg_ini.get("coin", "")))
    # `python minerar.py` (config Nerva) vai DIRETO minerar em foreground:
    # o próprio nervad com --start-mining sobe, sincroniza e minera, fazendo
    # o bind das portas. Subir um daemon de fundo antes causaria conflito de
    # porta ("another instance running"). O daemon de fundo (só sync) só é
    # útil quando o script NÃO minera: --saldo / --gerar-carteira.
    if (args.saldo or args.gerar_carteira) and eh_nerva \
            and not args.show and not args.benchmark:
        if garantir_daemon_nerva():
            print("  [minerar.py] Daemon Nerva carregado em segundo plano.\n")

    # --show: só exibe e sai
    if args.show:
        cfg = carregar_config()
        if not cfg:
            print("Nenhuma config salva ainda. Rode `python minerar.py` para configurar.")
            sys.exit(0)
        mostrar_config(cfg)
        sys.exit(0)

    # --saldo: consulta o saldo da carteira Nerva salva e sai
    if args.saldo:
        cfg = carregar_config() or config_padrao()
        if not cfg.get("address"):
            print("Nenhuma carteira salva ainda. Rode `python minerar.py --gerar-carteira`.")
            sys.exit(0)
        consultar_saldo_nerva(cfg)
        sys.exit(0)

    # --gerar-carteira: gera carteira Nerva a partir da private key (não minera)
    if args.gerar_carteira:
        if args.gerar_carteira == "__interativo__":
            res = gerar_carteira_nerva()
            if res:
                addr, sk, vk = res
                if perguntar_sn("Salvar este endereço na config para minerar?", "s"):
                    cfg = carregar_config() or config_padrao()
                    cfg["address"] = addr
                    cfg["nerva_spend_key"] = sk
                    cfg["nerva_view_key"] = vk
                    if "Nerva" not in str(cfg.get("coin", "")):
                        cfg["coin"] = "Nerva (XNV) — SOLO, sem pool"
                    salvar_config(cfg)
                    print(f"\n[OK] Endereço e chaves salvas em {CONFIG_FILE}.")
                    if perguntar_sn("Consultar o saldo desta carteira agora?", "s"):
                        consultar_saldo_nerva(cfg, em_segundo_plano=True)
                    if perguntar_sn("Iniciar a mineração agora?", "s"):
                        binario = localizar_nervad()
                        if not binario:
                            print(instrucoes_nerva(), file=sys.stderr)
                            sys.exit(2)
                        cfg["payout_min"] = "40 XNV"
                        cmd = montar_comando_nerva(binario, cfg, args)
                        sys.exit(rodar_com_dashboard(binario, cfg, cmd, args))
            sys.exit(0)
        else:
            addr, a_priv, v_priv, a_pub, v_pub = gerar_endereco_nerva(
                args.gerar_carteira)
            print("\n=====================================================")
            print("  CARTEIRA NERVA GERADA (linha de comando)")
            print("=====================================================")
            print(f"  Endereço (address):\n    {addr}")
            print(f"  Spend privada (hex):\n    {a_priv}")
            print(f"  View privada  (hex):\n    {v_priv}")
            print(f"  Spend pública (hex):\n    {a_pub}")
            print(f"  View pública  (hex):\n    {v_pub}")
            print("=====================================================")
            print("  Guarde as chaves privadas em lugar SEGURO.")
            print("=====================================================")
            sys.exit(0)

    # --benchmark: não precisa de config nem pool
    if args.benchmark:
        binario = localizar_binario()
        if not binario:
            print(instrucoes_build(), file=sys.stderr)
            sys.exit(2)
        cfg = config_padrao()
        cmd = montar_comando(binario, cfg, args)
        sys.exit(rodar_com_dashboard(binario, cfg, cmd, args))

    # --setup: reconfigure do zero e, se quiser, já minera
    if args.setup:
        cfg = configurar(coin_fixa="Nerva (XNV)" if args.nerva else None)
        if perguntar_sn("Iniciar a mineração agora?", "s"):
            if "Nerva" in cfg["coin"]:
                binario = localizar_nervad()
                if not binario:
                    print(instrucoes_nerva(), file=sys.stderr)
                    sys.exit(2)
                ok, _ = validar_endereco_nerva(cfg.get("address", ""))
                if not ok:
                    print("[minerar.py] Endereço Nerva inválido na config. "
                          "Rode: python minerar.py --setup --nerva", file=sys.stderr)
                    sys.exit(2)
                cmd = montar_comando_nerva(binario, cfg, args)
            else:
                binario = localizar_binario()
                if not binario:
                    print(instrucoes_build(), file=sys.stderr)
                    sys.exit(2)
                cmd = montar_comando(binario, cfg, args)
            sys.exit(rodar_com_dashboard(binario, cfg, cmd, args))
        sys.exit(0)

    # Carrega config salva ou constrói a partir de argumentos CLI
    cfg = carregar_config()

    if cfg is None:
        # Não há config salva. Se o usuário passou -o e -u na linha,
        # monta uma config provisória com os defaults; senão entra no
        # assistente interativo.
        if args.nerva:
            cfg = configurar(coin_fixa="Nerva (XNV)")
        elif args.url and args.user:
            cfg = config_padrao()
            cfg["url"] = args.url
            cfg["address"], _, cfg["worker"] = args.user.partition(".")
            cfg["worker"] = cfg["worker"] or "worker"
            if args.passwd is not None:
                cfg["pass"] = args.passwd
        else:
            cfg = configurar()
            if not perguntar_sn("Iniciar a mineração agora?", "s"):
                print("\nConfiguração salva. Para minerar depois, rode: python minerar.py")
                sys.exit(0)

    # --nerva pede a Nerva: se a config salva é de outra moeda, refaz para XNV
    if args.nerva and "Nerva" not in str(cfg.get("coin", "")):
        print("[minerar.py] Config salva é de outra moeda — refazendo para Nerva (XNV).\n")
        cfg = configurar(coin_fixa="Nerva (XNV)")

    # Sobrescritas por CLI (deste run) — mesmo se veio da config
    if args.url:
        cfg["url"] = args.url
    if args.user:
        cfg["address"], _, cfg["worker"] = args.user.partition(".")
    if args.passwd is not None:
        cfg["pass"] = args.passwd

    # Nerva = solo: usa o daemon oficial, não o minerd
    if args.nerva or "Nerva" in str(cfg.get("coin", "")):
        binario = localizar_nervad()
        if not binario:
            print(instrucoes_nerva(), file=sys.stderr)
            sys.exit(2)
        ok, motivo = validar_endereco_nerva(cfg.get("address", ""))
        if not ok:
            print(f"[minerar.py] Endereço Nerva inválido ({motivo}).", file=sys.stderr)
            print("[minerar.py] Corrija com: python minerar.py --setup --nerva", file=sys.stderr)
            sys.exit(2)
        cmd = montar_comando_nerva(binario, cfg, args)
        sys.exit(rodar_com_dashboard(binario, cfg, cmd, args))

    binario = localizar_binario()
    if not binario:
        print(instrucoes_build(), file=sys.stderr)
        sys.exit(2)

    cmd = montar_comando(binario, cfg, args)
    sys.exit(rodar_com_dashboard(binario, cfg, cmd, args))


if __name__ == "__main__":
    main()
