"""Regras do cartão de crédito (mesmas do programa original).

- Compra feita ATÉ o dia de fechamento entra na fatura do mesmo mês;
  depois do fechamento, entra na fatura do mês seguinte.
- Compra parcelada gera uma parcela por fatura (a última ajusta centavos).
- Limite comprometido = parcelas da fatura atual em diante.
"""
import calendar
from datetime import date


def somar_meses(ano, mes, soma):
    total = ano * 12 + (mes - 1) + soma
    return total // 12, total % 12 + 1


def dia_no_mes(ano, mes, dia):
    """Ajusta dias como 31 para meses mais curtos."""
    return min(dia, calendar.monthrange(ano, mes)[1])


def fatura_inicial(data, cartao):
    """(ano, mes) da fatura em que uma compra feita em 'data' cai."""
    fechamento = dia_no_mes(data.year, data.month, cartao["fechamento"])
    if data.day <= fechamento:
        return data.year, data.month
    return somar_meses(data.year, data.month, 1)


def vencimento_da_fatura(ano, mes, cartao):
    """Data de vencimento da fatura que fecha em (ano, mes)."""
    if cartao["vencimento"] <= cartao["fechamento"]:
        ano, mes = somar_meses(ano, mes, 1)
    return date(ano, mes, dia_no_mes(ano, mes, cartao["vencimento"]))


def parcelas_da_compra(compra, cartao):
    """Lista de (ano, mes, numero, valor) de cada parcela da compra."""
    n = compra["parcelas"]
    base = round(compra["valor"] / n, 2)
    ano, mes = fatura_inicial(compra["data"], cartao)
    resultado = []
    for numero in range(1, n + 1):
        if numero < n:
            valor = base
        else:
            valor = round(compra["valor"] - base * (n - 1), 2)
        a, m = somar_meses(ano, mes, numero - 1)
        resultado.append((a, m, numero, valor))
    return resultado


def parcelas_da_fatura(compras, cartao, ano, mes):
    """Parcelas da fatura (ano, mes): lista de (compra, numero, valor)."""
    itens = []
    for compra in compras:
        for a, m, numero, valor in parcelas_da_compra(compra, cartao):
            if (a, m) == (ano, mes):
                itens.append((compra, numero, valor))
    return itens


def limite_comprometido(compras, cartao, hoje):
    atual = fatura_inicial(hoje, cartao)
    total = 0.0
    for compra in compras:
        for a, m, _, valor in parcelas_da_compra(compra, cartao):
            if (a, m) >= atual:
                total += valor
    return total
