# Controle de Renda e Gastos — versão web

Mesma lógica do programa em Tkinter (rendas, gastos, filtros por período/mês e
cartões com faturas e parcelas), agora como site Flask com banco **PostgreSQL na nuvem**
e login por e-mail/senha. Cada usuário só enxerga os próprios dados.

## Estrutura

| Arquivo | Para quê |
|---|---|
| `app.py` | rotas, login, validações |
| `db.py` | banco (Postgres na nuvem; SQLite local se não houver `DATABASE_URL`) |
| `faturas.py` | regras do cartão (fechamento, parcelas, limite) |
| `templates/`, `static/` | telas, CSS e JS |
| `importar_json.py` | leva seus `.json` antigos para o banco |
| `render.yaml` | configuração de deploy no Render |

## Testar no seu computador (sem nuvem)

```bash
pip install -r requirements.txt
python app.py        # abre em http://127.0.0.1:5000
```
Sem `DATABASE_URL`, usa um arquivo `financas.db` local só para teste.

## Colocar no ar

### 1) Criar o banco na nuvem (grátis)
1. Crie uma conta em **neon.tech** → *New project*.
2. Copie a **connection string** (começa com `postgresql://...`).
   (Alternativa: Supabase → *Connect* → string do *Session pooler*.)

### 2) Subir o código no GitHub
Crie um repositório **privado** e envie esta pasta (o `.gitignore` já evita subir `.json` e `.env`).

### 3) Publicar no Render
1. render.com → *New* → *Blueprint* (ou *Web Service*) e escolha o repositório.
2. Variáveis de ambiente:
   - `DATABASE_URL` = a string do passo 1
   - `SECRET_KEY` = um texto longo aleatório (o `render.yaml` já gera sozinho)
3. Comando de início (se criar como Web Service): `gunicorn app:app`.
4. Abra a URL do site e **crie sua conta**. O cadastro fecha depois do primeiro usuário
   (para liberar mais pessoas, defina `ALLOW_SIGNUP=1`).

### 4) Importar seus dados antigos
Com a conta já criada, no seu computador:
```bash
export DATABASE_URL="postgresql://..."     # Windows PowerShell: $env:DATABASE_URL="..."
python importar_json.py --email voce@exemplo.com --pasta C:\caminho\dos\json
```

## Observações
- No plano grátis do Render o site "dorme" após alguns minutos parado; o primeiro acesso depois disso demora.
- Confira os limites atuais dos planos grátis do Neon/Render/Supabase antes de depender deles.
- Faça backup do banco de vez em quando (`pg_dump`, ou o recurso de backup do provedor).
- Segurança incluída: senhas com hash, proteção CSRF, cookies seguros, CSP e limite de tentativas de login.
- Valores ficam em `NUMERIC(14,2)` e datas em `DATE` (antes eram texto `dd/mm/aaaa`). Rendas antigas sem data aparecem com "-" e ficam fora de qualquer filtro de período, como no programa original.
