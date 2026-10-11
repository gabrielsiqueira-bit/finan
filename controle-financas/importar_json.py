"""Importa os dados do programa antigo (rendas.json, gastos.json,
cartoes.json, compras_cartao.json) para o banco.

1) Crie sua conta no site primeiro.
2) Rode (com DATABASE_URL apontando para o banco da nuvem):

   python importar_json.py --email voce@exemplo.com --pasta caminho/dos/json
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import db


def ler(pasta, nome):
    arquivo = pasta / nome
    if not arquivo.exists():
        print(f"  (não achei {nome}, pulando)")
        return []
    with arquivo.open(encoding="utf-8") as f:
        dados = json.load(f)
    return dados if isinstance(dados, list) else []


def data_ou_none(texto):
    try:
        return datetime.strptime(str(texto).strip(), "%d/%m/%Y").date()
    except ValueError:
        return None


def numero_valido(v):
    return isinstance(v, (int, float)) and v > 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--pasta", default=".")
    ap.add_argument("--forcar", action="store_true",
                    help="importa mesmo que a conta já tenha dados")
    args = ap.parse_args()
    pasta = Path(args.pasta)

    db.criar_tabelas()
    with db.Banco() as b:
        usuario = b.um("SELECT id FROM usuarios WHERE email = ?",
                       [args.email.strip().lower()])
        if not usuario:
            sys.exit("Usuário não encontrado. Crie a conta no site primeiro.")
        uid = usuario["id"]

        if not args.forcar:
            for tabela in ("rendas", "gastos", "cartoes"):
                n = b.um(f"SELECT COUNT(*) AS n FROM {tabela} "
                         "WHERE usuario_id = ?", [uid])["n"]
                if n:
                    sys.exit("Esta conta já tem dados. Use --forcar para "
                             "importar mesmo assim (pode duplicar).")

        n_r = n_g = n_ca = n_co = 0

        for r in ler(pasta, "rendas.json"):
            if (isinstance(r, dict) and isinstance(r.get("origem"), str)
                    and numero_valido(r.get("valor"))):
                b.executar(
                    "INSERT INTO rendas (usuario_id, origem, valor, descricao, data) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [uid, r["origem"], round(r["valor"], 2),
                     r.get("descricao", ""), db.p_data(data_ou_none(r.get("data")))])
                n_r += 1

        for g in ler(pasta, "gastos.json"):
            if (isinstance(g, dict) and isinstance(g.get("categoria"), str)
                    and numero_valido(g.get("valor"))):
                b.executar(
                    "INSERT INTO gastos (usuario_id, categoria, valor, descricao, data) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [uid, g["categoria"], round(g["valor"], 2),
                     g.get("descricao", ""), db.p_data(data_ou_none(g.get("data")))])
                n_g += 1

        ids_cartao = {}
        for c in ler(pasta, "cartoes.json"):
            if (isinstance(c, dict) and isinstance(c.get("nome"), str)
                    and numero_valido(c.get("limite"))
                    and isinstance(c.get("fechamento"), int)
                    and isinstance(c.get("vencimento"), int)):
                ids_cartao[c["nome"]] = b.inserir(
                    "INSERT INTO cartoes (usuario_id, nome, limite, fechamento, "
                    "vencimento) VALUES (?, ?, ?, ?, ?)",
                    [uid, c["nome"].strip(), round(c["limite"], 2),
                     c["fechamento"], c["vencimento"]])
                n_ca += 1

        for c in ler(pasta, "compras_cartao.json"):
            data = data_ou_none(c.get("data")) if isinstance(c, dict) else None
            if (data and c.get("cartao") in ids_cartao
                    and numero_valido(c.get("valor"))
                    and isinstance(c.get("parcelas"), int)
                    and 1 <= c["parcelas"] <= 60):
                b.executar(
                    "INSERT INTO compras (usuario_id, cartao_id, descricao, valor, "
                    "parcelas, data) VALUES (?, ?, ?, ?, ?, ?)",
                    [uid, ids_cartao[c["cartao"]], c.get("descricao", ""),
                     round(c["valor"], 2), c["parcelas"], db.p_data(data)])
                n_co += 1

    print(f"Importado: {n_r} rendas, {n_g} gastos, {n_ca} cartões, {n_co} compras.")


if __name__ == "__main__":
    main()
