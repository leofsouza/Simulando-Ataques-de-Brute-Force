## Desafio Santander - Cibersegurança 2025
# Projeto Simulando um Ataque de Brute Force de Senhas com Medusa e Kali Linux
Descrição do Desafio:
Este projeto consiste na implementação e documentação de um laboratório prático focado em ataques de Força Bruta (Brute Force).

Utilizando sistemas operacionais ofensivos (Kali Linux ou Parrot OS), foram simulados cenários reais de ataque contra ambientes vulneráveis, como Metasploitable 2 e DVWA. O objetivo principal é explorar o funcionamento de ferramentas como Medusa, ncrack, Hydra e BurpSuite para, posteriormente, desenvolver e exercitar medidas eficazes de prevenção e mitigação dessas vulnerabilidades.

## Reconhecimento de Infraestrutura e Fingerprinting com Nmap

* Utilizei o Nmap para realizar um scan de serviços de rede, buscando detectar portas abertas e versões de software vulneráveis no host alvo.

Esta atividade alinha-se à tática de Descoberta (Discovery) do framework MITRE ATT&CK, sendo especificamente catalogada como a técnica T1046 - Network Service Discovery.

https://github.com/user-attachments/assets/7390220a-964f-44de-8985-16426507abf9




## Especificações de Rede do Alvo
<img width="1365" height="767" alt="1" src="https://github.com/user-attachments/assets/76a2e532-201d-499a-b720-706e8fcd76eb" />

## Validação de Conectividade (Protocolo ICMP)
<img width="1365" height="767" alt="2" src="https://github.com/user-attachments/assets/9d56fb32-c858-4af4-815d-3073aa2e188d" />

## Criação de Wordlists para Autenticação
- A mesma lista será utilizada para realizar o ataque de força-bruta na aplicação Web do DVWA


<img width="1365" height="767" alt="4" src="https://github.com/user-attachments/assets/086862ad-521a-47c5-97b5-6beaf8391ff1" />

## Foi realizado um ataque de força bruta (Brute-Force) contra o serviço FTP (Porta 21) utilizando a ferramenta Ncrack para testar a resistência da autenticação.
Resultado da Execução: A ferramenta obteve êxito ao identificar credenciais válidas (username/password).

Análise de Impacto (Credential Reuse): A obtenção destas credenciais expõe o sistema ao risco de Reutilização de Senhas (Credential Stuffing). Um atacante poderia utilizar essas mesmas informações para tentar autenticação em outros serviços críticos (como SSH, Telnet ou Painéis Web) para ampliar seu acesso à infraestrutura.


<img width="1365" height="767" alt="5" src="https://github.com/user-attachments/assets/61dd7651-988e-4108-88a1-3384e3277760" />


## Validação de Credential Stuffing no SSH
Após a execução da técnica de Credential Stuffing, foi confirmado o reaproveitamento de credenciais. O mesmo par de usuário e senha permitiu a autenticação bem-sucedida no serviço SSH (Secure Shell) através da porta padrão 22.
<img width="1365" height="727" alt="7" src="https://github.com/user-attachments/assets/6e22cfa3-b8ce-40fe-ab94-7d76f3a43296" />


## Durante a fase de enumeração, a porta 80 (HTTP) foi identificada com o status Open (Aberta), indicando a presença de um serviço web ativo.
Inspeção de Código-Fonte via CLI (Curl).
Utilização do utilitário curl para requisições HTTP manuais. O objetivo foi inspecionar o código HTML bruto em busca de arquivos sensíveis, comentários de desenvolvedores ou tags de formulários (<form>) que pudessem servir como vetores de entrada.
<img width="1365" height="794" alt="8-curl-part1" src="https://github.com/user-attachments/assets/04f2651e-0873-40f9-9784-458d8659151d" />


Análise de Resposta HTTP: A requisição via método GET foi processada com sucesso pelo servidor, retornando o código de status 200 (OK). A análise do corpo da resposta confirmou o recebimento do código-fonte HTML da aplicação, validando a comunicação com o host alvo.

## Análise do Retorno do Comando Curl
<img width="1365" height="767" alt="8-curl-part2" src="https://github.com/user-attachments/assets/46a8444a-cf3c-41e4-8c18-23b94562c810" />

Identificação de Rotas e Links Internos: A análise do conteúdo revelou a presença de diversos hiperlinks e caminhos de diretórios internos. Essas referências expõem a estrutura de navegação da aplicação web hospedada no alvo (192.168.192.129).

## Identificação de Serviço FTP (Porta 21): Durante a fase de enumeração, a porta 21 foi detectada com status Open (Aberta), indicando a presença de um servidor FTP (File Transfer Protocol) ativo e acessível.
Validação de Acesso com Credenciais Comprometidas: Procedeu-se à tentativa de autenticação no sistema utilizando as credenciais previamente extraídas através da ferramenta Ncrack. O objetivo foi confirmar a validade dos dados de acesso num cenário real.
<img width="1365" height="767" alt="9-ftp-part1" src="https://github.com/user-attachments/assets/94925dc3-b3a1-4a04-97f2-a4b62df615c3" />


 Com a sessão estabelecida, avancei para a enumeração do sistema de arquivos. Ao acessar /home, verifiquei a existência da pasta do usuário msfadmin.

A análise das permissões revelou uma configuração interessante: enquanto o proprietário possui controle total, usuários externos possuem apenas permissão de execução. Isso significa que, embora seja possível acessar o diretório, a leitura e a escrita são negadas pelo sistema operacional, agindo como uma barreira de segurança.


<img width="1365" height="767" alt="9-ftp-part2" src="https://github.com/user-attachments/assets/971f5fc4-16bf-4f3e-a7ab-b62855234abb" />

## Auditoria de Autenticação Web com Burp Suite

Utilizando o proxy do Burp Suite Community, foi realizada a interceptação da requisição HTTP (método POST) gerada durante uma tentativa de login. Esta etapa é fundamental para identificar os parâmetros de entrada (username e password) que servirão como vetores para o ataque de força bruta.
 
<img width="1365" height="767" alt="10-Bforceweb-part1" src="https://github.com/user-attachments/assets/cfca2bd0-5e79-487a-b439-35b7c4560f42" />

__

Configuração do Ataque no Burp Suite

A imagem demonstra a preparação para um ataque de Brute-Force.

Painel de Requisição: Exibe o pacote HTTP POST interceptado, pronto para ser enviado ao módulo Intruder. Note os parâmetros username e password isolados no corpo da mensagem.

Painel de Dados: Apresenta a lista de payloads (dicionário de usuários e senhas) que serão injetados sequencialmente na aplicação.

Esse teste visa explorar a falta de limitação de tentativas de login no DVWA, simulando como um atacante testaria múltiplas credenciais em segundos.
--

<img width="1365" height="767" alt="10-Bforceweb-part2" src="https://github.com/user-attachments/assets/04bd3367-8363-4686-9831-5c5cc62c1dac" />

>
>

Nesta etapa, foi utilizado o módulo Repeater do Burp Suite para isolar e manipular requisições individuais contra o endpoint de autenticação do DVWA (/dvwa/login.php).

Diferente dos ataques automatizados, o Repeater permite um controle granular sobre o pacote HTTP POST. O objetivo foi alterar parâmetros específicos e reenviar a solicitação repetidamente para analisar como o servidor processa entradas inválidas ou maliciosas em tempo real.

Estrutura da Requisição Analisada:

```
POST /dvwa/login.php HTTP/1.1
Host: 192.168.192.129
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.129
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Referer: http://192.168.192.129/dvwa/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Connection: close
```

Request Body contém os parâmetros de autenticação submetidos para validação:

```
username=admin&password=admin
```

A utilização do módulo Repeater é fundamental para a análise granular da aplicação. Ele possibilita a manipulação iterativa dos parâmetros e a inspeção imediata das respostas HTTP.

Este processo manual permite mapear o comportamento do servidor, identificando discrepâncias nas respostas (como variação no Content-Length ou mensagens de erro verbosas) que revelam falhas na lógica de autenticação, validando o cenário para ataques automatizados subsequentes.

<img width="1365" height="767" alt="10-Bforceweb-part3" src="https://github.com/user-attachments/assets/a9edbbc6-97b5-4c92-8c3c-bb73a9ffa474" />



---


<img width="1365" height="767" alt="10-Bforceweb-part4" src="https://github.com/user-attachments/assets/be56d37b-36f6-40d0-b4d6-d5c3a9c13cc5" />


Nesta etapa, foi utilizado o módulo Repeater do Burp Suite para a execução de testes manuais de segurança. O objetivo foi auditar o comportamento da aplicação diante de diferentes inputs de credenciais.

A imagem demonstra a manipulação de uma requisição HTTP POST direcionada ao endpoint /dvwa/login.php. No corpo desta requisição, foram isolados os seguintes parâmetros para teste:

```
username=msfadmin&password=naftali&Login=Login
```

A integridade dos cabeçalhos HTTP foi preservada para emular com precisão o comportamento de um navegador padrão. Esta prática garante que a requisição seja interpretada pelo servidor como uma interação legítima de usuário.

```
POST /dvwa/login.php HTTP/1.1
Host: 192.168.192.129
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.129
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Referer: http://192.168.1.10/dvwa/login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.5
Connection: close
```

## Análise de Comportamento e Tratamento de Erros

O uso do Repeater permitiu um ciclo rápido de modificação e reenvio de parâmetros (username, password, Login), essencial para entender a lógica de validação do servidor.

Resultado do Teste Manual: Ao submeter credenciais inválidas, a aplicação retornou a mensagem "Login failed".

Conclusão da Fase de Enumeração: Esta resposta é um dado crítico. Ela estabelece uma linha de base (baseline) do comportamento da aplicação diante de falhas. A identificação desta mensagem de erro específica confirma que o sistema valida as entradas, mas também fornece a "assinatura" necessária para configurar filtros em ataques automatizados subsequentes (como Brute-Force), permitindo distinguir uma tentativa falha de um sucesso.

>
>

A análise da requisição revelou o retorno do status code 302 Found. Este comportamento de redirecionamento foi mapeado como um indicador chave da resposta da aplicação.

Com o padrão de resposta identificado, a requisição foi encaminhada para o módulo Intruder. O objetivo agora é automatizar o processo, executando um ataque de força bruta (Brute-Force) com base nos vetores de teste definidos.
<img width="1365" height="767" alt="10-Bforceweb-part5" src="https://github.com/user-attachments/assets/3580a134-525e-4ba4-b1ea-8f54b07f088f" />

>

Nota de Execução: A configuração visual dos payloads consistiu na inserção de marcadores nos campos de login e senha, utilizando wordlists personalizadas para cada vetor de entrada.

<img width="1365" height="767" alt="10-Bforcewebintruder-part5" src="https://github.com/user-attachments/assets/0d37d9f8-057d-43fe-b6e2-f7be1da80d7a" />

Durante a execução do ataque via Intruder contra o alvo (http://192.168.192.129), monitorou-se as respostas do servidor em busca de anomalias ou mensagens de sucesso.

Identificação do Sucesso (Request #2): A requisição de número 2 destacou-se por retornar a string de confirmação: You have logged in as 'admin'.

>
>
 ## Obtenção de Acesso Administrativo
<img width="1365" height="767" alt="10-Bforcewebintruder-part6" src="https://github.com/user-attachments/assets/d5a79fab-5da8-45f2-a477-78faa7c78df5" />

>
#  **Ajuste de Security Level** 


>

Para este teste, a aplicação web foi configurada com o Security Level definido como Medium.

<img width="1365" height="767" alt="10-Bforcelevel" src="https://github.com/user-attachments/assets/5e8fee9c-74a2-4dca-b7eb-407da343beb7" />


>
## Conclusão e Agradecimentos
Este projeto foi muito além de uma simulação de Brute-Force. Ele representou um estudo abrangente sobre diversos vetores de ataque e defesa, executado em um ambiente ético, controlado e autorizado.

O desenvolvimento deste laboratório faz parte do Desafio de Projeto (Simulando um Ataque de Brute Force de Senhas com Medusa e Kali Linux) do Bootcamp Santander Cibersegurança 2025. 



