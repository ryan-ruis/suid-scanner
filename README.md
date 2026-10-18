<div align="center">

# 🔎 SUID Scanner

**Auditoria defensiva de arquivos com permissão SUID em sistemas Linux**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Plataforma-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/Licença-MIT-green)
![Version](https://img.shields.io/badge/Versão-1.0.0-blue)

*Projeto educacional desenvolvido por **Ryan Ruis** para praticar Python, permissões Linux e fundamentos de segurança da informação.*

</div>

---

## 📌 Sobre o projeto

O **SUID Scanner** é uma ferramenta de linha de comando que procura arquivos regulares com o bit **SUID** ativado e apresenta informações úteis para uma revisão de segurança.

No Linux, o bit SUID (*Set User ID*) pode fazer um programa ser executado com o UID efetivo do proprietário do arquivo. Em muitos sistemas, ele aparece em executáveis legítimos que precisam realizar uma operação privilegiada. Por isso, encontrar um arquivo SUID **não significa automaticamente que existe uma vulnerabilidade**: é necessário entender a finalidade, a origem, o proprietário, as permissões e o comportamento do programa.

O scanner organiza os resultados por níveis de **risco potencial**, usando um catálogo local de nomes de programas conhecidos e recomendações iniciais. A classificação é apenas uma heurística para ajudar a priorizar a análise manual — não é uma confirmação de exploração ou vulnerabilidade.

## ✨ Funcionalidades

- 🔍 Procura arquivos regulares com o bit SUID ativado usando o utilitário `find`.
- 🛡️ Exibe permissões, caminho, proprietário e grupo do arquivo.
- 🚦 Atribui uma classificação heurística de risco potencial a alguns nomes conhecidos.
- 📋 Mostra observações e recomendações para apoiar a revisão manual.
- 📊 Apresenta um resumo com a quantidade de resultados por classificação.
- 📄 Pode exportar os resultados para JSON.
- 🧰 Trata erros esperados de caminho, execução do `find` e leitura de metadados.
- 🐧 Utiliza ferramentas nativas do Linux e a biblioteca Python Rich para a interface no terminal.

## 🖥️ Exemplo de uso

A saída depende dos arquivos e das permissões do sistema analisado. Exemplo ilustrativo:

```text
╭──────────────────────────────────────────────╮
│ SUID Scanner v1.0.0                           │
│ Ferramenta educacional para auditoria Linux   │
│ Diretório analisado: /usr/bin                 │
╰──────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Caminho              ┃ Permissões ┃ Proprietário:Grupo┃ Risco potencial┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ /usr/bin/exemplo     │ -rwsr-xr-x │ root:root         │ REVISAR        │
└──────────────────────┴────────────┴───────────────────┴────────────────┘

Resumo
Arquivos SUID encontrados: 1
REVISAR: 1
```

> **Importante:** o exemplo acima é fictício. Os resultados reais variam de acordo com a distribuição, os pacotes instalados e as permissões locais.

## ⚙️ Requisitos e compatibilidade

| Requisito | Detalhes |
|---|---|
| Sistema operacional | Linux (por exemplo, Kali Linux, Debian, Ubuntu e derivados) |
| Python | **Python 3.10 ou superior** |
| Dependência Python | `rich` |
| Ferramenta do sistema | `find` (normalmente fornecido pelo pacote `findutils`) |
| Permissões | Execute com sua conta normal primeiro. Use privilégios elevados somente se estiver autorizado e se precisar ampliar a cobertura da auditoria. |
| Internet | Não é necessária durante a execução, após a instalação da dependência |

### Limitações de compatibilidade

- O programa foi pensado para **Linux**. Não é destinado a Windows nativo ou macOS.
- A opção `--path` usa a sintaxe e o comportamento do `find` disponível no sistema.
- Sem privilégios administrativos, alguns diretórios podem não ser acessíveis. Nesse caso, o scanner pode apresentar um aviso e deixar de encontrar arquivos nessas áreas.
- O catálogo de classificação é local, limitado e baseado no nome do executável. Ele pode não reconhecer binários personalizados, versões específicas ou configurações relevantes.
- Um nível de risco alto não comprova que o arquivo é vulnerável; um resultado `REVISAR` também não significa que o arquivo seja seguro.
- O scanner **não explora vulnerabilidades, não tenta obter acesso root e não altera permissões ou arquivos**.

## 🚀 Instalação

### 1. Verifique os requisitos

No terminal Linux:

```bash
python3 --version
find --version
```

Confirme que o Python é 3.10 ou superior e que o comando `find` está instalado.

### 2. Clone o repositório

Depois de publicar o projeto no GitHub, clone o repositório:

```bash
git clone https://github.com/ryan-ruis/suid-scanner.git
cd suid-scanner
```

Ou baixe os arquivos `suid_scanner.py` e `requirements.txt` para a mesma pasta.

### 3. Crie um ambiente virtual (recomendado)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Se o comando `venv` não estiver disponível na sua distribuição, instale o pacote correspondente ao Python fornecido pelo sistema.

### 4. Instale a dependência

```bash
python -m pip install -r requirements.txt
```

Se preferir instalar diretamente:

```bash
python -m pip install "rich>=13.7.0,<15.0.0"
```

## ▶️ Como usar

### Verificar todo o sistema

```bash
python3 suid_scanner.py
```

Por padrão, a ferramenta começa em `/`. A varredura pode demorar e gerar avisos de acesso negado.

### Verificar apenas um diretório

```bash
python3 suid_scanner.py --path /usr/bin
```

Use um diretório existente ao qual você tenha autorização para realizar a auditoria.

### Exportar os resultados para JSON

```bash
python3 suid_scanner.py --path /usr/bin --json relatorio.json
```

O relatório contém a versão da ferramenta, o caminho analisado e os resultados coletados. Ele pode ser usado para documentação, comparação e análise posterior.

### Consultar a versão e a ajuda

```bash
python3 suid_scanner.py --version
python3 suid_scanner.py --help
```

## 🧠 O que significa SUID?

SUID é uma permissão especial de arquivos Unix/Linux. Quando configurada em um executável, pode fazer com que ele seja executado com o UID efetivo do proprietário do arquivo, em vez de simplesmente usar o UID efetivo do usuário que o iniciou.

Um exemplo comum de representação nas permissões é:

```text
-rwsr-xr-x
```

O `s` na posição de execução do proprietário indica que o bit SUID está ativo. Se o proprietário for `root`, o programa pode operar com privilégios efetivos de root — desde que seu comportamento e o sistema permitam isso. Esse mecanismo é usado legitimamente por alguns programas, mas precisa ser revisado com cuidado.

## 🧪 Tecnologias utilizadas

- **Python 3** — estrutura e lógica da aplicação.
- **`subprocess`** — execução do comando `find`.
- **`os` e `stat`** — consulta de caminhos, metadados e permissões.
- **`argparse`** — argumentos de linha de comando.
- **`json`** — exportação dos resultados.
- **Rich** — tabelas, painéis e saída colorida no terminal.
- **Git e GitHub** — versionamento e publicação do projeto.

## 🔐 Uso responsável

Utilize esta ferramenta somente em computadores, servidores e ambientes nos quais você tenha autorização para realizar auditorias. Faça uma cópia dos dados importantes antes de qualquer ação corretiva e valide manualmente cada resultado antes de alterar permissões.

O SUID Scanner é uma ferramenta educacional e **não substitui** ferramentas profissionais, análise de código, revisão de configuração, atualização de pacotes ou avaliação conduzida por um profissional de segurança.

## 🗺️ Próximas melhorias

- [ ] Adicionar testes automatizados.
- [ ] Permitir exportação CSV.
- [ ] Melhorar o catálogo com informações versionadas e fontes de referência.
- [ ] Adicionar filtros por nível de risco.
- [ ] Incluir mais detalhes de metadados para apoiar a auditoria.

## 👨‍💻 Autor

**Ryan Ruis** — estudante de Segurança da Informação e entusiasta de Python, Linux e cibersegurança.

## 📄 Licença

Este projeto é distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para os termos completos.
