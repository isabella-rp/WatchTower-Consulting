# WatchTower-Consulting

WatchTower Consulting: "A vigilância que blinda o seu capital"

Este repositório contém um projeto que faz parte da matéria de Análise e Gestão de Riscos, do curso de Segurança da Informação - FATECSCS.
Ele é parte do monitoramento automatizado da WatchTower Consulting (empresa fictícia), desenvolvido para garantir a resiliência operacional e a segurança de ativos críticos de um Banco Digital.

- Sobre o Projeto

O sistema realiza rondas automatizadas no banco de dados do NIST através da API NVD v2.0, buscando por vulnerabilidades recém-publicadas que fazem parte do nosso rol de monitoramento. A automação foi pensada após debatermos a preocupação que poderíamos deixar alguma vulnerabilidade passar ou acabar demorando demais para detectá-la. 

- Os ativos monitorados são:

Windows Server 2022

SQL Server 2022

Cisco Catalyst 9500 

Windows 11 Pro 

Microsoft Edge

- Como funciona:

O robô foi projetado com a intenção de usufruir da menor Janela de Exposição possível, seguindo o fluxo abaixo

Ronda: O GitHub Actions "acorda" o script a cada 30 minutos.

Identificação: O script consulta o NIST buscando falhas publicadas nas últimas 48 horas.

Filtragem: Compara as falhas encontradas com o arquivo memorizadas.txt para evitar alertas duplicados.

Alerta: Caso uma nova falha seja detectada, um e-mail formatado é enviado imediatamente para a equipe de Resposta a Incidentes, que assim, encaminha para o professor. 

- Estrutura do Repositório:

monitor_watchtower_cloud.py: O "cérebro" do robô (Python).

.github/workflows/monitoramento.yml: O "motor" que roda o código sozinho.

memorizadas.txt: O banco de dados de memória do sistema.

README.md: Este guia de governança.

- Segurança: 

Este projeto segue as melhores práticas de segurança

Gestão de Segredos: Nenhuma credencial de e-mail ou senha está exposta no código. Utilizamos o GitHub Secrets para gerenciar as variáveis de ambiente EMAIL_USER e EMAIL_PASS.

Cadeia de Custódia: Cada execução do robô é registrada nos logs do GitHub Actions, permitindo auditoria completa.
