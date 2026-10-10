"""Camada de banco de dados.

- Em produção (variável DATABASE_URL apontando para um Postgres na nuvem)
  usa PostgreSQL via psycopg.
- Sem DATABASE_URL usa um arquivo SQLite local (financas.db), só para testes.
"""
import os
import sqlite3
from datetime import date
from decimal import Decimal

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

USA_PG = DATABASE_URL.startswith("postgresql://")
SQLITE_PATH = os.environ.get("SQLITE_PATH", "financas.db")

if USA_PG:
    import psycopg
    from psycopg.rows import dict_row

COLUNAS_DATA = {"data"}


def conectar():
    if USA_PG:
        # prepare_threshold=None: compatível com poolers (PgBouncer/Neon/Supabase).
        return psycopg.connect(
            DATABASE_URL, row_factory=dict_row, prepare_threshold=None
        )
    con = sqlite3.connect(SQLITE_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def p_data(d):
    """Converte date para o formato aceito pelo banco em uso."""
    if d is None:
        return None
    return d if USA_PG else d.isoformat()


def _normalizar(linha):
    saida = {}
    for chave, valor in dict(linha).items():
        if isinstance(valor, Decimal):
            valor = float(valor)
        elif chave in COLUNAS_DATA and isinstance(valor, str):
            valor = date.fromisoformat(valor) if valor else None
        saida[chave] = valor
    return saida


class Banco:
    """Uso: with Banco() as b: b.todos(...). Faz commit/rollback sozinho."""

    def __enter__(self):
        self.con = conectar()
        return self

    def __exit__(self, tipo, valor, tb):
        try:
            if tipo is None:
                self.con.commit()
            else:
                self.con.rollback()
        finally:
            self.con.close()

    @staticmethod
    def _sql(sql):
        return sql.replace("?", "%s") if USA_PG else sql

    def executar(self, sql, params=()):
        cur = self.con.cursor()
        cur.execute(self._sql(sql), tuple(params))
        return cur

    def todos(self, sql, params=()):
        return [_normalizar(r) for r in self.executar(sql, params).fetchall()]

    def um(self, sql, params=()):
        linha = self.executar(sql, params).fetchone()
        return _normalizar(linha) if linha else None

    def inserir(self, sql, params=()):
        if USA_PG:
            return self.executar(sql + " RETURNING id", params).fetchone()["id"]
        return self.executar(sql, params).lastrowid


def criar_tabelas():
    if USA_PG:
        pk, dt, num, inteiro = "BIGSERIAL PRIMARY KEY", "DATE", "NUMERIC(14,2)", "BIGINT"
        agora = "TIMESTAMPTZ NOT NULL DEFAULT now()"
    else:
        pk, dt, num, inteiro = "INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT", "REAL", "INTEGER"
        agora = "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"

    comandos = [
        f"""CREATE TABLE IF NOT EXISTS usuarios (
            id {pk},
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            criado_em {agora}
        )""",
        f"""CREATE TABLE IF NOT EXISTS rendas (
            id {pk},
            usuario_id {inteiro} NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            origem TEXT NOT NULL,
            valor {num} NOT NULL CHECK (valor > 0),
            descricao TEXT NOT NULL DEFAULT '',
            data {dt}
        )""",
        f"""CREATE TABLE IF NOT EXISTS gastos (
            id {pk},
            usuario_id {inteiro} NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            categoria TEXT NOT NULL,
            valor {num} NOT NULL CHECK (valor > 0),
            descricao TEXT NOT NULL DEFAULT '',
            data {dt}
        )""",
        f"""CREATE TABLE IF NOT EXISTS cartoes (
            id {pk},
            usuario_id {inteiro} NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            nome TEXT NOT NULL,
            limite {num} NOT NULL CHECK (limite > 0),
            fechamento INTEGER NOT NULL CHECK (fechamento BETWEEN 1 AND 31),
            vencimento INTEGER NOT NULL CHECK (vencimento BETWEEN 1 AND 31),
            UNIQUE (usuario_id, nome)
        )""",
        f"""CREATE TABLE IF NOT EXISTS compras (
            id {pk},
            usuario_id {inteiro} NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
            cartao_id {inteiro} NOT NULL REFERENCES cartoes(id) ON DELETE CASCADE,
            descricao TEXT NOT NULL,
            valor {num} NOT NULL CHECK (valor > 0),
            parcelas INTEGER NOT NULL CHECK (parcelas BETWEEN 1 AND 60),
            data {dt} NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_rendas_usuario_data ON rendas (usuario_id, data)",
        "CREATE INDEX IF NOT EXISTS idx_gastos_usuario_data ON gastos (usuario_id, data)",
        "CREATE INDEX IF NOT EXISTS idx_compras_cartao ON compras (usuario_id, cartao_id)",
    ]
    with Banco() as b:
        for comando in comandos:
            b.executar(comando)
