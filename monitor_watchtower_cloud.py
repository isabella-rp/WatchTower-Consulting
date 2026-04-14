import requests
import smtplib
import time
import sys
import os
import csv
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone


EMAIL = os.environ.get("EMAIL_USER")
SENHA_APP = os.environ.get("EMAIL_PASS")
NIST_API_KEY = os.environ.get("NIST_API_KEY") 

ATIVOS = [
    "Windows Server 2022",
    "SQL Server 2022",
    "Cisco Catalyst 9500",
    "Windows 11",
    "Microsoft Edge"
]

DB_VULNS = "memorizadas.txt"
PLANILHA_CSV = "historico_vulnerabilidades.csv"

def log(mensagem):
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {mensagem}")
    sys.stdout.flush()

def carregar_vulnerabilidades_conhecidas():
    try:
        with open(DB_VULNS, "r") as arquivo:
            return set(arquivo.read().splitlines())
    except FileNotFoundError:
        return set()

def salvar_na_planilha(data_pub, cve_id, ativo, descricao, score, severidade):
    arquivo_novo = not os.path.exists(PLANILHA_CSV)
    with open(PLANILHA_CSV, mode='a', newline='', encoding='utf-8-sig') as f:
        if arquivo_novo: f.write("sep=;\n")
        escritor = csv.writer(f, delimiter=';')
        if arquivo_novo:
            escritor.writerow(['Data Pub.', 'ID CVE', 'Ativo Impactado', 'Gravidade', 'Score', 'Descrição Técnica'])
        escritor.writerow([data_pub, cve_id, ativo, severidade, score, descricao])

def salvar_nova_vulnerabilidade(cve_id):
    with open(DB_VULNS, "a") as arquivo:
        arquivo.write(cve_id + "\n")

def enviar_alerta_pessoal(cve_id, descricao, ativo, score, severidade):
    cor_severidade = "#d9534f" if severidade in ["CRITICAL", "HIGH"] else "#f0ad4e"
    
    link_cve = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    assunto = f"[WATCHTOWER] ALERTA {severidade}: {ativo} ({cve_id})"
    
    corpo = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <div style="background-color: #f8f9fa; padding: 20px; border-left: 10px solid {cor_severidade};">
            <h2 style="color: {cor_severidade}; margin-top: 0;">[WATCHTOWER - ALERTA DE VULNERABILIDADE]</h2>
            
            <p>Prezado Prof. Nilton,</p>
            <p>Nossa plataforma de monitoramento identificou uma vulnerabilidade crítica que impacta diretamente o ambiente do Banco Digital.</p>
            
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Ativo Impactado:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{ativo}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>ID da Falha:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{cve_id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><strong>Gravidade:</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;"><span style="color: {cor_severidade}; font-weight: bold;">{severidade} (Score: {score})</span></td>
                </tr>
            </table>

            <p><strong>Descrição Técnica:</strong><br>{descricao}</p>

            <div style="margin-top: 25px; text-align: center;">
                <a href="{link_cve}" 
                   style="background-color: #0275d8; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                   ACESSAR ANÁLISE OFICIAL (NIST NVD)
                </a>
            </div>

            <p style="font-size: 12px; color: #777; margin-top: 30px;">
                <em>Ação Recomendada: Iniciar plano de mitigação e verificar disponibilidade de patch de segurança imediatamente.</em>
            </p>
            <hr style="border: 0; border-top: 1px solid #ccc;">
            <p>Atenciosamente,<br><strong>Equipe WatchTower Consulting</strong></p>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEText(corpo, 'html')
    msg['Subject'] = assunto
    msg['From'] = EMAIL
    msg['To'] = EMAIL # Ou o e-mail do professor se ele quiser receber direto

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, SENHA_APP)
            server.send_message(msg)
        log(f"Alerta enviado com link: {cve_id}")
    except Exception as e:
        log(f"Erro ao enviar e-mail: {e}")

def buscar_no_nist():
    conhecidas = carregar_vulnerabilidades_conhecidas()
    data_hoje = datetime.now(timezone.utc)
    
    DIAS_DE_BUSCA = 7 
    data_alvo = data_hoje - timedelta(days=DIAS_DE_BUSCA)
    
    data_inicio = data_alvo.strftime('%Y-%m-%dT%H:%M:%S.000')
    data_fim = data_hoje.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'User-Agent': 'WatchTower-Monitor/3.0'}
    if NIST_API_KEY:
        headers['apiKey'] = NIST_API_KEY

    total_novas = 0

    for ativo in ATIVOS:
        log(f"Varrendo NIST para: {ativo}...")
        params = {
            'keywordSearch': ativo,
            'lastModStartDate': data_inicio, # Mudança para pegar atualizações recentes
            'lastModEndDate': data_fim
        }
        
        try:
            res = requests.get(base_url, headers=headers, params=params, timeout=60)
            
            if res.status_code == 200:
                dados = res.json()
                vulnerabilidades = dados.get('vulnerabilities', [])
                log(f"   > Encontradas {len(vulnerabilidades)} ocorrências.")

                for v in vulnerabilidades:
                    c = v.get('cve', {})
                    cve_id = c.get('id')

                    if cve_id not in conhecidas:
                        desc = c.get('descriptions', [{}])[0].get('value', 'Sem descrição')
                        metrics = c.get('metrics', {})
                        score = "N/A"
                        sev = "UNKNOWN"

                        # Tenta pegar V3.1, depois V3.0, depois V2
                        if 'cvssMetricV31' in metrics:
                            score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                            sev = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                        elif 'cvssMetricV30' in metrics:
                            score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                            sev = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']

                        enviar_alerta_pessoal(cve_id, desc, ativo, score, sev)
                        salvar_na_planilha(c.get('published'), cve_id, ativo, desc, score, sev)
                        salvar_nova_vulnerabilidade(cve_id)
                        total_novas += 1
            else:
                log(f"   [!] Erro {res.status_code} no NIST para {ativo}")
        
        except Exception as e:
            log(f"   [!] Erro de conexão: {e}")
        
        time.sleep(6 if NIST_API_KEY else 15)

    log(f"Ronda finalizada. Total de novas falhas: {total_novas}")

if __name__ == "__main__":
    buscar_no_nist()
