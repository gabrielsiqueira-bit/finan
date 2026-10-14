import calendar
import hmac
import math
import os
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from urllib.parse import parse_qsl, urlencode
from zoneinfo import ZoneInfo

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import db
import faturas

# -----------------------------
# CONFIGURACAO
# -----------------------------

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

if not os.environ.get("SECRET_KEY") and db.USA_PG:
    raise RuntimeError("Defina a variável de ambiente SECRET_KEY.")
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or "chave-so-para-testes-locais",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "1" if db.USA_PG else "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

CATEGORIAS = [
    "Alimentação", "Moradia", "Transporte", "Saúde",
    "Educação", "Lazer", "Contas", "Outros"
]
MESES = [
    "Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
    "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"
]

# Tabelas de lançamentos (nome da coluna principal em cada uma).
LANCAMENTOS = {
    "rendas": {"campo": "origem", "rotulo": "Origem da renda",
               "coluna": "ORIGEM", "titulo": "Rendas"},
    "gastos": {"campo": "categoria", "rotulo": "Categoria",
               "coluna": "CATEGORIA", "titulo": "Gastos"},
}

try:
    FUSO = ZoneInfo(os.environ.get("APP_TZ", "America/Sao_Paulo"))
except Exception:
    FUSO = timezone(timedelta(hours=-3))

db.criar_tabelas()


# -----------------------------
# FUNCOES AUXILIARES
# -----------------------------

def hoje():
    return datetime.now(FUSO).date()


def formatar_moeda(valor):
    texto = f"{valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return f"R$ {texto}"


def formatar_data(d):
    return d.strftime("%d/%m/%Y") if d else "-"


app.jinja_env.filters["moeda"] = formatar_moeda
app.jinja_env.filters["br"] = formatar_data
app.jinja_env.filters["valor_campo"] = lambda v: f"{v:.2f}".replace(".", ",")


def converter_valor(texto):
    """Aceita formatos como 2500,50 ou 2.500,50."""
    texto = (texto or "").strip().replace("R$", "").replace(" ", "")
    if not texto:
        raise ValueError("Informe um valor.")
    if "," in texto:
        texto = texto.replace(".", "").replace(",", ".")
    valor = float(texto)
    if not math.isfinite(valor) or valor > 1_000_000_000:
        raise ValueError("Valor inválido.")
    return round(valor, 2)


def converter_data(texto):
    """Aceita aaaa-mm-dd (campos de data do navegador) ou dd/mm/aaaa."""
    texto = (texto or "").strip()
    for formato in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(texto, formato).date()
        except ValueError:
            pass
    raise ValueError("Data inválida.")


def erro(msg):
    flash(msg, "erro")


def ok(msg):
    flash(msg, "ok")


def voltar(endpoint, url_args=None, **extra):
    """Redireciona de volta mantendo só parâmetros de filtro conhecidos."""
    permitidos = {"de", "ate", "mes", "ano", "cartao"}
    params = {k: v for k, v in parse_qsl(request.form.get("qs", ""))
              if k in permitidos}
    params.update(extra)
    url = url_for(endpoint, **(url_args or {}))
    return redirect(url + ("?" + urlencode(params) if params else ""))


def ids_do_formulario():
    ids = []
    for valor in request.form.getlist("ids"):
        if valor.isdigit():
            ids.append(int(valor))
    return ids


# -----------------------------
# SEGURANCA: login, CSRF, cabecalhos
# -----------------------------

def login_required(funcao):
    @wraps(funcao)
    def interna(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return funcao(*args, **kwargs)
    return interna


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def verificar_csrf():
    if request.method == "POST":
        enviado = request.form.get("csrf_token", "")
        esperado = session.get("csrf", "")
        if not esperado or not hmac.compare_digest(enviado, esperado):
            abort(400, "Sessão expirada. Volte e tente novamente.")


@app.after_request
def cabecalhos(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    return resp


_falhas = {}


def login_bloqueado():
    agora = time.time()
    recentes = [t for t in _falhas.get(request.remote_addr, []) if agora - t < 600]
    _falhas[request.remote_addr] = recentes
    return len(recentes) >= 5


def registrar_falha():
    _falhas.setdefault(request.remote_addr, []).append(time.time())


def cadastro_liberado():
    """Só o primeiro usuário pode se cadastrar (ou se ALLOW_SIGNUP=1)."""
    if os.environ.get("ALLOW_SIGNUP") == "1":
        return True
    with db.Banco() as b:
        return b.um("SELECT COUNT(*) AS n FROM usuarios")["n"] == 0


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if login_bloqueado():
            erro("Muitas tentativas. Aguarde alguns minutos.")
            return render_template("auth.html", modo="login",
                                   pode_cadastrar=cadastro_liberado())
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        with db.Banco() as b:
            usuario = b.um("SELECT * FROM usuarios WHERE email = ?", [email])
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            session.clear()
            session.permanent = True
            session["uid"] = usuario["id"]
            session["email"] = usuario["email"]
            return redirect(url_for("inicio"))
        registrar_falha()
        erro("E-mail ou senha incorretos.")
    return render_template("auth.html", modo="login",
                           pode_cadastrar=cadastro_liberado())


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if not cadastro_liberado():
        abort(404)
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        if "@" not in email or len(email) > 200:
            erro("Informe um e-mail válido.")
        elif len(senha) < 8:
            erro("A senha precisa ter pelo menos 8 caracteres.")
        elif senha != request.form.get("senha2", ""):
            erro("As senhas não conferem.")
        else:
            with db.Banco() as b:
                if b.um("SELECT id FROM usuarios WHERE email = ?", [email]):
                    erro("Este e-mail já está cadastrado.")
                else:
                    uid = b.inserir(
                        "INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)",
                        [email, generate_password_hash(senha)])
                    session.clear()
                    session.permanent = True
                    session["uid"] = uid
                    session["email"] = email
                    return redirect(url_for("inicio"))
    return render_template("auth.html", modo="cadastro", pode_cadastrar=True)


@app.post("/sair")
def sair():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------
# VISAO GERAL
# -----------------------------

def variacao(atual, anterior):
    """Variação percentual (inteira) ou None se não há base de comparação."""
    if anterior <= 0:
        return None
    return round((atual - anterior) / anterior * 100)


def montar_grafico(meses_serie, por_mes, ano, mes):
    """Coordenadas do gráfico de barras (rendas x gastos), para o SVG."""
    largura, base_y, altura = 640, 204, 176
    maior = max([1.0] + [v for m in meses_serie
                         for v in (por_mes[m]["rendas"], por_mes[m]["gastos"])])
    grupo = largura / len(meses_serie)
    larg_barra, folga = 32, 6
    inicio_x = (grupo - (2 * larg_barra + folga)) / 2

    def barra(valor, x):
        h = 0 if valor <= 0 else max(valor / maior * altura, 3)
        return {"x": round(x, 1), "y": round(base_y - h, 1),
                "h": round(h, 1), "w": larg_barra, "valor": round(valor, 2)}

    grupos = []
    for i, m in enumerate(meses_serie):
        x0 = i * grupo + inicio_x
        grupos.append({
            "rotulo": MESES[m[1] - 1][:3],
            "centro": round(i * grupo + grupo / 2, 1),
            "atual": m == (ano, mes),
            "renda": barra(por_mes[m]["rendas"], x0),
            "gasto": barra(por_mes[m]["gastos"], x0 + larg_barra + folga),
        })
    return {"largura": largura, "base_y": base_y, "rotulo_y": base_y + 22,
            "altura_total": base_y + 32, "grupos": grupos}


@app.get("/")
@login_required
def inicio():
    agora = hoje()
    mes = request.args.get("mes", type=int)
    ano = request.args.get("ano", type=int)
    if not (mes and ano and 1 <= mes <= 12 and 1900 <= ano <= 2100):
        ano, mes = agora.year, agora.month
    anterior = faturas.somar_meses(ano, mes, -1)
    seguinte = faturas.somar_meses(ano, mes, 1)
    serie = [faturas.somar_meses(ano, mes, k) for k in range(-5, 1)]
    de = date(serie[0][0], serie[0][1], 1)
    ate = date(ano, mes, calendar.monthrange(ano, mes)[1])
    uid = session["uid"]

    with db.Banco() as b:
        sql = ("SELECT {campo} AS nome, valor, data FROM {t} "
               "WHERE usuario_id = ? AND data >= ? AND data <= ?")
        linhas_r = b.todos(sql.format(campo="origem", t="rendas"),
                           [uid, db.p_data(de), db.p_data(ate)])
        linhas_g = b.todos(sql.format(campo="categoria", t="gastos"),
                           [uid, db.p_data(de), db.p_data(ate)])
        recentes = []
        for tabela, tipo in (("rendas", "renda"), ("gastos", "gasto")):
            campo = LANCAMENTOS[tabela]["campo"]
            for r in b.todos(
                    f"SELECT {campo} AS nome, valor, descricao, data FROM {tabela} "
                    "WHERE usuario_id = ? "
                    "ORDER BY (data IS NULL), data DESC, id DESC LIMIT 5", [uid]):
                r["tipo"] = tipo
                recentes.append(r)
        lista_cartoes = buscar_cartoes(b)
        compras = {c["id"]: compras_do_cartao(b, c["id"]) for c in lista_cartoes}

    por_mes = {m: {"rendas": 0.0, "gastos": 0.0} for m in serie}
    cat_atual, cat_anterior = {}, {}
    for r in linhas_r:
        por_mes[(r["data"].year, r["data"].month)]["rendas"] += r["valor"]
    for g in linhas_g:
        chave = (g["data"].year, g["data"].month)
        por_mes[chave]["gastos"] += g["valor"]
        if chave == (ano, mes):
            cat_atual[g["nome"]] = cat_atual.get(g["nome"], 0.0) + g["valor"]
        elif chave == anterior:
            cat_anterior[g["nome"]] = cat_anterior.get(g["nome"], 0.0) + g["valor"]

    total_r = round(por_mes[(ano, mes)]["rendas"], 2)
    total_g = round(por_mes[(ano, mes)]["gastos"], 2)
    ant_r = round(por_mes[anterior]["rendas"], 2)
    ant_g = round(por_mes[anterior]["gastos"], 2)

    categorias = [
        {"nome": nome, "total": round(v, 2),
         "pct": round(v / total_g * 100) if total_g else 0,
         "var": variacao(v, cat_anterior.get(nome, 0.0))}
        for nome, v in sorted(cat_atual.items(), key=lambda kv: -kv[1])]

    recentes.sort(key=lambda r: (r["data"] or date.min), reverse=True)

    cartoes_resumo = []
    for c in lista_cartoes:
        a, m = faturas.fatura_inicial(agora, c)
        itens = faturas.parcelas_da_fatura(compras[c["id"]], c, a, m)
        comprometido = faturas.limite_comprometido(compras[c["id"]], c, agora)
        venc = faturas.vencimento_da_fatura(a, m, c)
        cartoes_resumo.append({
            "id": c["id"], "nome": c["nome"], "limite": c["limite"],
            "fatura": round(sum(v for _, _, v in itens), 2),
            "vencimento": venc, "dias": (venc - agora).days,
            "pct": round(comprometido / c["limite"] * 100) if c["limite"] else 0,
            "disponivel": c["limite"] - comprometido})

    return render_template(
        "inicio.html", aba="inicio", meses=MESES, mes=mes, ano=ano, hoje=agora,
        anterior=anterior, seguinte=seguinte,
        total_rendas=total_r, total_gastos=total_g,
        var_rendas=variacao(total_r, ant_r), var_gastos=variacao(total_g, ant_g),
        nome_anterior=MESES[anterior[1] - 1],
        categorias=categorias, grafico=montar_grafico(serie, por_mes, ano, mes),
        cartoes=cartoes_resumo, recentes=recentes[:6])


# -----------------------------
# FILTRO DE PERIODO (rendas e gastos)
# -----------------------------

def ler_filtro():
    args = request.args
    agora = hoje()
    filtro = {"de": None, "ate": None, "descricao": "Todos os registros",
              "params": {}, "mes": agora.month, "ano": agora.year}

    if args.get("de") or args.get("ate"):
        try:
            de = converter_data(args["de"]) if args.get("de") else None
            ate = converter_data(args["ate"]) if args.get("ate") else None
        except ValueError:
            erro("Data inválida no filtro.")
            return filtro
        if de and ate and de > ate:
            erro("A data inicial não pode ser maior que a final.")
            return filtro
        if de and ate:
            desc = f"Período: {formatar_data(de)} a {formatar_data(ate)}"
        elif de:
            desc = f"A partir de {formatar_data(de)}"
        else:
            desc = f"Até {formatar_data(ate)}"
        filtro.update(de=de, ate=ate, descricao=desc)
        filtro["params"] = {k: args[k] for k in ("de", "ate") if args.get(k)}

    elif args.get("mes") or args.get("ano"):
        try:
            mes, ano = int(args.get("mes", "")), int(args.get("ano", ""))
            if not (1 <= mes <= 12 and 1900 <= ano <= 2100):
                raise ValueError
        except ValueError:
            erro("Escolha um mês e um ano válidos (ex.: 2026).")
            return filtro
        ultimo = calendar.monthrange(ano, mes)[1]
        filtro.update(
            de=date(ano, mes, 1), ate=date(ano, mes, ultimo),
            descricao=f"Mês: {MESES[mes - 1]}/{ano}",
            mes=mes, ano=ano, params={"mes": mes, "ano": ano})
    return filtro


def clausula_periodo(filtro):
    sql, params = "", []
    if filtro["de"]:
        sql += " AND data >= ?"
        params.append(db.p_data(filtro["de"]))
    if filtro["ate"]:
        sql += " AND data <= ?"
        params.append(db.p_data(filtro["ate"]))
    return sql, params


# -----------------------------
# RENDAS E GASTOS
# -----------------------------

def pagina_lancamentos(tabela):
    cfg = LANCAMENTOS[tabela]
    filtro = ler_filtro()
    where, params = clausula_periodo(filtro)
    uid = session["uid"]
    with db.Banco() as b:
        registros = b.todos(
            f"SELECT * FROM {tabela} WHERE usuario_id = ?{where} "
            "ORDER BY (data IS NULL), data DESC, id DESC", [uid] + params)
        resumo = {}
        for t in LANCAMENTOS:
            resumo[t] = b.um(
                "SELECT COALESCE(SUM(valor), 0) AS total, COUNT(*) AS n "
                f"FROM {t} WHERE usuario_id = ?{where}", [uid] + params)
    return render_template(
        "lancamentos.html", aba=tabela, endpoint=tabela, cfg=cfg,
        registros=registros, filtro=filtro, meses=MESES,
        categorias=CATEGORIAS, hoje=hoje(),
        total_rendas=resumo["rendas"]["total"],
        total_gastos=resumo["gastos"]["total"],
        n_rendas=resumo["rendas"]["n"], n_gastos=resumo["gastos"]["n"])


def ler_lancamento(tabela, data_vazia):
    """Valida o formulário de renda/gasto.

    Devolve (campo, valor, descricao, data) ou None (o erro já foi avisado).
    Se a data vier em branco, usa 'data_vazia'.
    """
    cfg = LANCAMENTOS[tabela]
    campo = request.form.get(cfg["campo"], "").strip()
    descricao = request.form.get("descricao", "").strip()
    if not campo or not request.form.get("valor", "").strip():
        erro(f"Preencha {cfg['rotulo'].lower()} e o valor.")
        return None
    if len(campo) > 80 or len(descricao) > 200:
        erro("Texto muito longo.")
        return None
    try:
        valor = converter_valor(request.form["valor"])
    except ValueError:
        erro("Digite um valor válido, por exemplo: 2500,50.")
        return None
    if valor <= 0:
        erro("O valor precisa ser maior que zero.")
        return None
    try:
        data = converter_data(request.form.get("data")) \
            if request.form.get("data", "").strip() else data_vazia
    except ValueError:
        erro("Data inválida.")
        return None
    return campo, valor, descricao, data


def adicionar_lancamento(tabela):
    cfg = LANCAMENTOS[tabela]
    dados = ler_lancamento(tabela, hoje())
    if dados is None:
        return voltar(tabela)
    campo, valor, descricao, data = dados
    with db.Banco() as b:
        b.executar(
            f"INSERT INTO {tabela} (usuario_id, {cfg['campo']}, valor, "
            "descricao, data) VALUES (?, ?, ?, ?, ?)",
            [session["uid"], campo, valor, descricao, db.p_data(data)])
    ok("Registro adicionado.")
    return voltar(tabela)


def buscar_lancamento(tabela, id):
    with db.Banco() as b:
        registro = b.um(f"SELECT * FROM {tabela} WHERE usuario_id = ? AND id = ?",
                        [session["uid"], id])
    if not registro:
        abort(404)
    return registro


def pagina_editar(tabela, id):
    registro = buscar_lancamento(tabela, id)
    return render_template(
        "editar.html", aba=tabela, endpoint=tabela, cfg=LANCAMENTOS[tabela],
        registro=registro, filtro=ler_filtro(), categorias=CATEGORIAS)


def salvar_edicao(tabela, id):
    cfg = LANCAMENTOS[tabela]
    buscar_lancamento(tabela, id)  # 404 se não existir ou for de outro usuário
    # Data em branco = registro sem data (como as rendas antigas importadas).
    dados = ler_lancamento(tabela, None)
    if dados is None:
        return voltar(tabela + "_editar", url_args={"id": id})
    campo, valor, descricao, data = dados
    with db.Banco() as b:
        b.executar(
            f"UPDATE {tabela} SET {cfg['campo']} = ?, valor = ?, descricao = ?, "
            "data = ? WHERE usuario_id = ? AND id = ?",
            [campo, valor, descricao, db.p_data(data), session["uid"], id])
    ok("Registro atualizado.")
    return voltar(tabela)


def remover_lancamentos(tabela):
    ids = ids_do_formulario()
    if not ids:
        erro("Selecione um ou mais registros para remover.")
    else:
        marcas = ",".join("?" * len(ids))
        with db.Banco() as b:
            b.executar(
                f"DELETE FROM {tabela} WHERE usuario_id = ? AND id IN ({marcas})",
                [session["uid"]] + ids)
        ok(f"{len(ids)} registro(s) removido(s).")
    return voltar(tabela)


@app.get("/rendas")
@login_required
def rendas():
    return pagina_lancamentos("rendas")


@app.post("/rendas")
@login_required
def rendas_adicionar():
    return adicionar_lancamento("rendas")


@app.post("/rendas/remover")
@login_required
def rendas_remover():
    return remover_lancamentos("rendas")


@app.get("/rendas/<int:id>/editar")
@login_required
def rendas_editar(id):
    return pagina_editar("rendas", id)


@app.post("/rendas/<int:id>/editar")
@login_required
def rendas_editar_salvar(id):
    return salvar_edicao("rendas", id)


@app.get("/gastos")
@login_required
def gastos():
    return pagina_lancamentos("gastos")


@app.post("/gastos")
@login_required
def gastos_adicionar():
    return adicionar_lancamento("gastos")


@app.post("/gastos/remover")
@login_required
def gastos_remover():
    return remover_lancamentos("gastos")


@app.get("/gastos/<int:id>/editar")
@login_required
def gastos_editar(id):
    return pagina_editar("gastos", id)


@app.post("/gastos/<int:id>/editar")
@login_required
def gastos_editar_salvar(id):
    return salvar_edicao("gastos", id)


# -----------------------------
# CARTOES
# -----------------------------

def buscar_cartoes(b):
    return b.todos("SELECT * FROM cartoes WHERE usuario_id = ? ORDER BY nome",
                   [session["uid"]])


def compras_do_cartao(b, cartao_id):
    return b.todos(
        "SELECT * FROM compras WHERE usuario_id = ? AND cartao_id = ? "
        "ORDER BY data, id", [session["uid"], cartao_id])


@app.get("/cartoes")
@login_required
def cartoes():
    with db.Banco() as b:
        lista = buscar_cartoes(b)
        cartao = next((c for c in lista
                       if c["id"] == request.args.get("cartao", type=int)),
                      lista[0] if lista else None)
        compras = compras_do_cartao(b, cartao["id"]) if cartao else []

    ctx = {"aba": "cartoes", "cartoes": lista, "cartao": cartao,
           "meses": MESES, "hoje": hoje()}
    if cartao:
        atual = faturas.fatura_inicial(hoje(), cartao)
        mes = request.args.get("mes", type=int)
        ano = request.args.get("ano", type=int)
        if not (mes and ano and 1 <= mes <= 12 and 1900 <= ano <= 2100):
            ano, mes = atual
        itens = faturas.parcelas_da_fatura(compras, cartao, ano, mes)
        comprometido = faturas.limite_comprometido(compras, cartao, hoje())
        ctx.update(
            mes=mes, ano=ano, itens=itens, comprometido=comprometido,
            disponivel=cartao["limite"] - comprometido,
            total_fatura=sum(v for _, _, v in itens),
            vencimento=faturas.vencimento_da_fatura(ano, mes, cartao))
    return render_template("cartoes.html", **ctx)


@app.post("/cartoes/compra")
@login_required
def compra_adicionar():
    uid = session["uid"]
    with db.Banco() as b:
        cartao = b.um("SELECT * FROM cartoes WHERE id = ? AND usuario_id = ?",
                      [request.form.get("cartao_id", type=int), uid])
        if not cartao:
            erro("Cartão não encontrado.")
            return voltar("cartoes")
        compras = compras_do_cartao(b, cartao["id"])

        descricao = request.form.get("descricao", "").strip()
        if not descricao or not request.form.get("valor", "").strip():
            erro("Preencha a descrição e o valor total da compra.")
            return voltar("cartoes", cartao=cartao["id"])
        if len(descricao) > 200:
            erro("Descrição muito longa.")
            return voltar("cartoes", cartao=cartao["id"])
        try:
            valor = converter_valor(request.form["valor"])
            if valor <= 0:
                raise ValueError
        except ValueError:
            erro("Digite um valor válido, por exemplo: 1200,00.")
            return voltar("cartoes", cartao=cartao["id"])
        try:
            parcelas = int(request.form.get("parcelas", "").strip() or "1")
            if not 1 <= parcelas <= 60:
                raise ValueError
        except ValueError:
            erro("Digite um número de parcelas entre 1 e 60.")
            return voltar("cartoes", cartao=cartao["id"])
        try:
            data = converter_data(request.form.get("data")) \
                if request.form.get("data", "").strip() else hoje()
        except ValueError:
            erro("Data inválida.")
            return voltar("cartoes", cartao=cartao["id"])

        disponivel = cartao["limite"] - faturas.limite_comprometido(
            compras, cartao, hoje())
        if valor > disponivel and not request.form.get("excedente"):
            erro(f"Esta compra ({formatar_moeda(valor)}) é maior que o limite "
                 f"disponível ({formatar_moeda(disponivel)}). Marque "
                 "'Permitir exceder o limite' para adicionar mesmo assim.")
            return voltar("cartoes", cartao=cartao["id"])

        b.executar(
            "INSERT INTO compras (usuario_id, cartao_id, descricao, valor, "
            "parcelas, data) VALUES (?, ?, ?, ?, ?, ?)",
            [uid, cartao["id"], descricao, valor, parcelas, db.p_data(data)])

    ano, mes = faturas.fatura_inicial(data, cartao)
    ok("Compra adicionada.")
    return voltar("cartoes", cartao=cartao["id"], mes=mes, ano=ano)


@app.post("/cartoes/compra/remover")
@login_required
def compra_remover():
    ids = ids_do_formulario()
    if not ids:
        erro("Selecione uma ou mais linhas da fatura para remover.")
    else:
        marcas = ",".join("?" * len(ids))
        with db.Banco() as b:
            b.executar(
                f"DELETE FROM compras WHERE usuario_id = ? AND id IN ({marcas})",
                [session["uid"]] + ids)
        ok("Compra(s) removida(s) por inteiro (todas as parcelas).")
    return voltar("cartoes")


@app.get("/cartoes/gerenciar")
@login_required
def cartoes_gerenciar():
    with db.Banco() as b:
        lista = buscar_cartoes(b)
    return render_template("gerenciar.html", aba="cartoes", cartoes=lista)


@app.post("/cartoes/novo")
@login_required
def cartao_novo():
    nome = request.form.get("nome", "").strip()
    try:
        limite = converter_valor(request.form.get("limite"))
        fechamento = int(request.form.get("fechamento", "").strip())
        vencimento = int(request.form.get("vencimento", "").strip())
        if (not nome or len(nome) > 60 or limite <= 0
                or not (1 <= fechamento <= 31 and 1 <= vencimento <= 31)):
            raise ValueError
    except ValueError:
        erro("Informe nome, limite maior que zero e dias entre 1 e 31.")
        return redirect(url_for("cartoes_gerenciar"))

    with db.Banco() as b:
        if b.um("SELECT id FROM cartoes WHERE usuario_id = ? AND LOWER(nome) = ?",
                [session["uid"], nome.lower()]):
            erro("Já existe um cartão com esse nome.")
        else:
            b.executar(
                "INSERT INTO cartoes (usuario_id, nome, limite, fechamento, "
                "vencimento) VALUES (?, ?, ?, ?, ?)",
                [session["uid"], nome, limite, fechamento, vencimento])
            ok("Cartão adicionado.")
    return redirect(url_for("cartoes_gerenciar"))


@app.post("/cartoes/remover")
@login_required
def cartao_remover():
    ids = ids_do_formulario()
    if not ids:
        erro("Selecione um ou mais cartões para remover.")
    else:
        marcas = ",".join("?" * len(ids))
        with db.Banco() as b:
            b.executar(
                f"DELETE FROM compras WHERE usuario_id = ? AND cartao_id IN ({marcas})",
                [session["uid"]] + ids)
            b.executar(
                f"DELETE FROM cartoes WHERE usuario_id = ? AND id IN ({marcas})",
                [session["uid"]] + ids)
        ok("Cartão(ões) e compras removidos.")
    return redirect(url_for("cartoes_gerenciar"))


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
